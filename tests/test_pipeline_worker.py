import json
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.pipeline import PipelineError
from fuzz_target_scout.pipeline_worker import PipelineWorker
from fuzz_target_scout.pipeline_worker import WorkerResult
from fuzz_target_scout.resources import ResourceAllocation, ResourceSnapshot


class PipelineWorkerTests(unittest.TestCase):
    def test_worker_runs_independent_fuzz_jobs_in_parallel(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory)
            for index in range(2):
                self._job(
                    runs,
                    f"fuzz-job-{index}",
                    created=f"2026-01-0{index + 1}T00:00:00Z",
                    stage="fuzzing",
                    status="ready",
                )
            snapshot = ResourceSnapshot(8, 8192, 6144, ("test",))
            allocation = ResourceAllocation(2, 2, 1536, 576, 1, 1024, snapshot)
            barrier = threading.Barrier(2)
            observed_allocations = []

            worker = object.__new__(PipelineWorker)
            worker.runs_root = runs
            worker.pipeline = {}
            worker.progress = lambda _message: None
            worker.housekeeper = None

            def fake_advance(job_id, *, setup_only, allocation):
                if setup_only:
                    return WorkerResult(job_id, "ready", "fuzzing", "ready")
                observed_allocations.append(allocation)
                barrier.wait(timeout=2)
                return WorkerResult(job_id, "exhausted", "complete", "fuzz")

            worker._advance = fake_advance
            with patch(
                "fuzz_target_scout.pipeline_worker.plan_resources",
                return_value=allocation,
            ):
                results = worker.run(2)

        self.assertEqual(len(results), 2)
        self.assertEqual(observed_allocations, [allocation, allocation])

    def test_validation_stage_dispatches_to_separate_agent(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory)
            self._job(
                runs, "validation-job", created="2026-01-01T00:00:00Z",
                stage="validation", status="validation_pending",
            )

            class StubValidation:
                def validate(self, _job_id):
                    return {"state": {"status": "ready_for_human", "stage": "complete"}}

            worker = object.__new__(PipelineWorker)
            worker.runs_root = runs
            worker.pipeline = {"max_generation_cycles": 2}
            worker.progress = lambda _message: None
            worker.validation_runner = StubValidation()
            result = worker._advance("validation-job", setup_only=False)
            self.assertEqual(result.action, "validate")
            self.assertEqual(result.status, "ready_for_human")

    def test_repeated_worker_failure_stops_at_configured_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory)
            self._job(
                runs, "failure-job", created="2026-01-01T00:00:00Z",
                stage="build", status="worker_failed",
            )
            job = runs / "failure-job"
            worker = object.__new__(PipelineWorker)
            worker.runs_root = runs
            worker.pipeline = {"max_stage_failures": 2}
            worker._record_worker_error("failure-job", RuntimeError("failed"))
            worker._record_worker_error("failure-job", RuntimeError("failed again"))
            state = json.loads((job / "state.json").read_text())
            self.assertEqual(state["status"], "manual_review")
            self.assertEqual(state["attempts"]["worker_failures"], 2)

    def test_advance_stops_immediately_for_manual_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory)
            self._job(
                runs,
                "review-job",
                created="2026-01-01T00:00:00Z",
                stage="quartet_gate",
                status="quartet_review_required",
            )
            worker = object.__new__(PipelineWorker)
            worker.runs_root = runs
            worker.pipeline = {"max_generation_cycles": 2}
            worker.progress = lambda _message: None
            result = worker._advance("review-job", setup_only=True)
            self.assertEqual(result.action, "needs_attention")

    def test_integration_stage_dispatches_to_integrate(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory)
            self._job(
                runs,
                "integration-job",
                created="2026-01-01T00:00:00Z",
                stage="integration",
                status="prepared",
            )

            class StubRunner:
                @staticmethod
                def integrate(_job_id):
                    raise PipelineError("integrate was called")

            worker = object.__new__(PipelineWorker)
            worker.runs_root = runs
            worker.pipeline = {"max_generation_cycles": 2}
            worker.progress = lambda _message: None
            worker.runner = StubRunner()
            result = worker._advance("integration-job", setup_only=True)
            self.assertEqual(result.action, "integrate")
            self.assertIn("integrate was called", result.error)

    def test_worker_dispatches_pending_afl_cmplog_lane(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory)
            self._job(
                runs,
                "afl-job",
                created="2026-01-01T00:00:00Z",
                stage="fuzzing",
                status="afl_cmplog_pending",
            )

            class StubRunner:
                @staticmethod
                def afl_cmplog(_job_id):
                    raise PipelineError("afl lane was called")

            worker = object.__new__(PipelineWorker)
            worker.runs_root = runs
            worker.pipeline = {"max_generation_cycles": 2}
            worker.progress = lambda _message: None
            worker.runner = StubRunner()
            result = worker._advance("afl-job", setup_only=False)
            self.assertEqual(result.action, "afl_cmplog")
            self.assertIn("afl lane was called", result.error)

    def _job(
        self,
        root: Path,
        job_id: str,
        *,
        created: str,
        stage: str,
        status: str,
    ) -> None:
        job = root / job_id
        job.mkdir()
        (job / "state.json").write_text(
            json.dumps(
                {
                    "job_id": job_id,
                    "created_at": created,
                    "stage": stage,
                    "status": status,
                }
            )
        )

    def test_setup_only_selects_oldest_ready_job_without_fuzzing(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory)
            self._job(
                runs,
                "new-job",
                created="2026-01-02T00:00:00Z",
                stage="fuzzing",
                status="ready",
            )
            self._job(
                runs,
                "old-job",
                created="2026-01-01T00:00:00Z",
                stage="fuzzing",
                status="ready",
            )
            worker = object.__new__(PipelineWorker)
            worker.runs_root = runs
            worker.pipeline = {"max_generation_cycles": 2}
            worker.progress = lambda _message: None
            worker.runner = object()
            results = worker.run(1, setup_only=True)
            self.assertEqual(results[0].job_id, "old-job")
            self.assertEqual(results[0].action, "ready")

    def test_queue_runs_triage_but_skips_jobs_waiting_for_human(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory)
            self._job(
                runs,
                "triage-job",
                created="2026-01-01T00:00:00Z",
                stage="triage",
                status="triage_pending",
            )
            self._job(
                runs,
                "review-job",
                created="2026-01-02T00:00:00Z",
                stage="quartet_gate",
                status="quartet_review_required",
            )
            self._job(
                runs,
                "ready-job",
                created="2026-01-03T00:00:00Z",
                stage="fuzzing",
                status="ready",
            )
            worker = object.__new__(PipelineWorker)
            worker.runs_root = runs
            self.assertEqual(worker._next_job(set()), "triage-job")
            self.assertEqual(worker._next_job({"triage-job"}), "ready-job")


if __name__ == "__main__":
    unittest.main()
