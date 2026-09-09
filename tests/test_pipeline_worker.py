import json
import tempfile
import unittest
from pathlib import Path

from fuzz_target_scout.pipeline import PipelineError
from fuzz_target_scout.pipeline_worker import PipelineWorker


class PipelineWorkerTests(unittest.TestCase):
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
