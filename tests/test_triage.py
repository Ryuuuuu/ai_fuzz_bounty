import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.triage import TriageRunner, extract_signature


ASAN_LOG = """ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234
    #0 0x1234 in parse /src/parser.cc:10:3
    #1 0x5678 in LLVMFuzzerTestOneInput /src/fuzz.cc:8:2
"""


class TriageTests(unittest.TestCase):
    def test_signature_ignores_process_addresses(self):
        first, frames = extract_signature(ASAN_LOG)
        second, _ = extract_signature(ASAN_LOG.replace("0x1234", "0xabcd"))
        self.assertEqual(first, second)
        self.assertTrue(first)
        self.assertIn("0xADDR", frames[0])

    def test_no_crashes_finishes_as_exhausted(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, job_id, job_dir = self._fixture(Path(directory), crash=False)
            result = runner.triage(job_id, use_ai=False)
            self.assertEqual(result["validated_group_count"], 0)
            self.assertEqual(result["state"]["status"], "exhausted")
            self.assertFalse((job_dir / "artifacts" / "validation-handoff.json").exists())

    def test_three_matching_reproductions_create_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, job_id, job_dir = self._fixture(Path(directory), crash=True)
            with patch.object(runner, "_minimize", return_value=None), patch.object(
                runner, "_reproduce", return_value=(1, ASAN_LOG)
            ):
                result = runner.triage(job_id, use_ai=False)
            self.assertEqual(result["validated_group_count"], 1)
            self.assertEqual(result["state"]["status"], "ready_for_human")
            handoff = json.loads(
                (job_dir / "artifacts" / "validation-handoff.json").read_text()
            )
            self.assertTrue(handoff["human_review_required"])
            self.assertFalse(handoff["automatic_submission"])
            self.assertEqual(
                len(
                    handoff["validated_groups"][0]["representative"][
                        "reproduction_attempts"
                    ]
                ),
                3,
            )

    @staticmethod
    def _fixture(root: Path, *, crash: bool):
        job_id = "org-parser-" + "a" * 12
        job_dir = root / job_id
        artifacts = job_dir / "artifacts"
        crash_dir = job_dir / "crashes" / "fuzz_parser"
        artifacts.mkdir(parents=True)
        crash_dir.mkdir(parents=True)
        (job_dir / "validation").mkdir()
        crash_names = []
        if crash:
            (crash_dir / "crash-1").write_bytes(b"bad input")
            crash_names = ["crash-1"]
        (job_dir / "job.json").write_text(
            json.dumps(
                {
                    "source": {"repository": "org/parser", "commit": "a" * 40},
                    "authorization": {"program_url": "https://example.invalid/bounty"},
                }
            )
        )
        (job_dir / "state.json").write_text(
            json.dumps({"stage": "triage", "status": "triage_pending", "attempts": {}})
        )
        (artifacts / "fuzz-run.json").write_text(
            json.dumps({"fuzz_target": "fuzz_parser", "crash_files": crash_names})
        )
        (artifacts / "build-manifest.json").write_text(
            json.dumps(
                {
                    "fuzz_targets": ["fuzz_parser"],
                    "output_directory": str(job_dir / "build-output" / "asan"),
                    "sanitizer": "address",
                }
            )
        )
        config = {
            "pipeline": {
                "runs_path": str(root),
                "triage_max_crashes": 20,
                "triage_reproduction_attempts": 3,
                "triage_timeout_seconds": 60,
                "input_timeout_seconds": 2,
                "container_memory_mb": 1024,
            }
        }
        return TriageRunner(config), job_id, job_dir


if __name__ == "__main__":
    unittest.main()
