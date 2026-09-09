import json
import tempfile
import unittest
from pathlib import Path

from fuzz_target_scout.pipeline_worker import PipelineWorker


class PipelineWorkerTests(unittest.TestCase):
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
