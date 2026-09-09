import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.operations import Housekeeper, directory_size, pipeline_overview


class OperationsTests(unittest.TestCase):
    def test_prunes_oldest_corpus_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                path = corpus / str(index)
                path.write_bytes(bytes([index]) * 10)
                timestamp = time.time() - (30 - index)
                os.utime(path, (timestamp, timestamp))
            evidence = job / "validation" / "case" / "minimized"
            evidence.parent.mkdir(parents=True)
            evidence.write_bytes(b"evidence")
            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]):
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            self.assertFalse((corpus / "0").exists())
            self.assertTrue((corpus / "1").exists())
            self.assertTrue(evidence.is_file())
            self.assertEqual(result["jobs"][0]["removed_files"], 1)

    def test_disk_limit_moves_active_job_to_manual_resource_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]):
                result = Housekeeper(self._config(root, job_disk_limit_mb=0)).run(job.name)
            state = json.loads((job / "state.json").read_text())
            self.assertTrue(result["jobs"][0]["over_limit"])
            self.assertEqual(state["status"], "resource_limit_required")

    def test_overview_includes_disk_and_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            value = pipeline_overview(root)
            self.assertEqual(value["job_count"], 1)
            self.assertEqual(value["jobs"][0]["job_id"], job.name)
            self.assertEqual(value["jobs"][0]["fuzz_remaining_seconds"], 100.0)
            self.assertEqual(value["total_disk_bytes"], directory_size(job))

    @staticmethod
    def _job(root: Path) -> Path:
        job = root / "org-parser-aaaaaaaaaaaa"
        (job / "artifacts").mkdir(parents=True)
        (job / "corpus").mkdir()
        (job / "logs").mkdir()
        (job / "validation").mkdir()
        (job / "job.json").write_text(json.dumps({
            "source": {"repository": "org/parser", "commit": "a" * 40},
            "route": {"name": "oss_fuzz_existing"},
            "budgets": {"fuzz_seconds": 100},
        }))
        (job / "state.json").write_text(json.dumps({
            "job_id": job.name, "status": "ready", "stage": "fuzzing",
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        }))
        return job

    @staticmethod
    def _config(root: Path, **overrides):
        values = {
            "runs_path": str(root), "corpus_max_files": 100,
            "corpus_limit_mb": 100, "log_max_files": 10,
            "runtime_retention_hours": 24, "job_disk_limit_mb": 100,
        }
        values.update(overrides)
        return {"pipeline": values}


if __name__ == "__main__":
    unittest.main()
