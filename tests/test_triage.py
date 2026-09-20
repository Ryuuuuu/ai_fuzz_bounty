import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.pipeline import PipelineError
from fuzz_target_scout.triage import TriageRunner, extract_signature


ASAN_LOG = """ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234
    #0 0x1234 in parse /src/parser.cc:10:3
    #1 0x5678 in LLVMFuzzerTestOneInput /src/fuzz.cc:8:2
"""


class TriageTests(unittest.TestCase):
    def test_rejects_unknown_state_triage_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "e" * 12
            job = root / job_id
            job.mkdir()
            (job / "job.json").write_text("{}")
            (job / "state.json").write_text(
                json.dumps(
                    {
                        "stage": "triage",
                        "status": "triage_pending",
                        "triage_artifact": "../escape.json",
                    }
                )
            )
            runner = object.__new__(TriageRunner)
            runner.runs_root = root
            with self.assertRaisesRegex(PipelineError, "unsupported triage artifact"):
                runner.triage(job_id, use_ai=False)

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
            self.assertEqual(result["state"]["status"], "validation_pending")
            self.assertEqual(result["state"]["stage"], "validation")
            self.assertEqual(
                result["groups"][0]["classification"]["verdict"],
                "validated_sanitizer_finding",
            )
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

    def test_nonreproducing_oom_is_archived_and_fuzzing_resumes(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, job_id, job_dir = self._fixture(Path(directory), crash=True)
            crash_dir = job_dir / "crashes" / "fuzz_parser"
            (crash_dir / "crash-1").rename(crash_dir / "fuzz_parser-oom-deadbeef")
            artifact = job_dir / "artifacts" / "fuzz-run.json"
            payload = json.loads(artifact.read_text())
            payload["crash_files"] = ["fuzz_parser-oom-deadbeef"]
            artifact.write_text(json.dumps(payload))
            (job_dir / "artifacts" / "fuzz-progress.json").write_text(
                json.dumps({"completed_seconds": 1000, "resource_limit_events": 1})
            )
            with patch.object(runner, "_minimize", return_value=None), patch.object(
                runner, "_reproduce", return_value=(0, "")
            ):
                result = runner.triage(job_id, use_ai=False)

            self.assertTrue(result["resource_only_false_positive"])
            self.assertEqual(result["state"]["status"], "ready")
            self.assertEqual(result["state"]["stage"], "fuzzing")
            self.assertFalse(any(crash_dir.iterdir()))
            self.assertTrue(
                (Path(result["resource_event_archive"]) / "fuzz_parser-oom-deadbeef").is_file()
            )
            progress = json.loads(
                (job_dir / "artifacts" / "fuzz-progress.json").read_text()
            )
            self.assertEqual(progress["resource_limit_events"], 2)

    def test_nonreproducing_empty_leak_artifact_resumes_fuzzing(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, job_id, job_dir = self._fixture(Path(directory), crash=True)
            crash_dir = job_dir / "crashes" / "fuzz_parser"
            crash = crash_dir / "crash-1"
            crash.write_bytes(b"")
            artifact = job_dir / "artifacts" / "fuzz-run.json"
            payload = json.loads(artifact.read_text())
            payload["sanitizer_summaries"] = [
                "ERROR: LeakSanitizer: detected memory leaks",
                "SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).",
            ]
            artifact.write_text(json.dumps(payload))
            progress_path = job_dir / "artifacts" / "fuzz-progress.json"
            progress_path.write_text(
                json.dumps({"completed_seconds": 1000, "resource_limit_events": 0})
            )
            with patch.object(runner, "_minimize", return_value=None), patch.object(
                runner, "_reproduce", return_value=(0, "")
            ):
                result = runner.triage(job_id, use_ai=False)

            self.assertTrue(result["auto_resumable_false_positive"])
            self.assertFalse(result["resource_only_false_positive"])
            self.assertEqual(result["false_positive_reason"], "process_exit_leak")
            self.assertEqual(result["state"]["status"], "ready")
            self.assertEqual(result["state"]["stage"], "fuzzing")
            self.assertFalse(any(crash_dir.iterdir()))
            self.assertTrue(
                (Path(result["false_positive_archive"]) / "crash-1").is_file()
            )
            progress = json.loads(progress_path.read_text())
            self.assertEqual(progress["resource_limit_events"], 0)

    def test_nonreproducing_timeout_resumes_fuzzing(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, job_id, job_dir = self._fixture(Path(directory), crash=True)
            crash_dir = job_dir / "crashes" / "fuzz_parser"
            timeout = crash_dir / "fuzz_parser-timeout-deadbeef"
            (crash_dir / "crash-1").rename(timeout)
            artifact = job_dir / "artifacts" / "fuzz-run.json"
            payload = json.loads(artifact.read_text())
            payload["crash_files"] = [timeout.name]
            artifact.write_text(json.dumps(payload))
            with patch.object(runner, "_minimize", return_value=None), patch.object(
                runner, "_reproduce", return_value=(0, "")
            ):
                result = runner.triage(job_id, use_ai=False)

            self.assertTrue(result["auto_resumable_false_positive"])
            self.assertEqual(
                result["false_positive_reason"], "timeout_not_reproduced"
            )
            self.assertEqual(result["state"]["status"], "ready")
            self.assertEqual(result["state"]["stage"], "fuzzing")
            self.assertFalse(any(crash_dir.iterdir()))
            self.assertTrue(
                (Path(result["false_positive_archive"]) / timeout.name).is_file()
            )

    def test_mixed_nonreproducing_runtime_artifacts_resume_fuzzing(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, job_id, job_dir = self._fixture(Path(directory), crash=True)
            crash_dir = job_dir / "crashes" / "fuzz_parser"
            timeout = crash_dir / "fuzz_parser-timeout-deadbeef"
            (crash_dir / "crash-1").rename(timeout)
            empty_leak = crash_dir / "fuzz_parser-crash-empty"
            empty_leak.write_bytes(b"")
            artifact = job_dir / "artifacts" / "fuzz-run.json"
            payload = json.loads(artifact.read_text())
            payload["crash_files"] = [timeout.name, empty_leak.name]
            payload["sanitizer_summaries"] = [
                "ERROR: LeakSanitizer: detected memory leaks",
                "SUMMARY: libFuzzer: timeout",
                "SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).",
            ]
            artifact.write_text(json.dumps(payload))
            with patch.object(runner, "_minimize", return_value=None), patch.object(
                runner, "_reproduce", return_value=(0, "")
            ):
                result = runner.triage(job_id, use_ai=False)

            self.assertTrue(result["auto_resumable_false_positive"])
            self.assertEqual(
                result["false_positive_reason"],
                "mixed_runtime_artifacts_not_reproduced",
            )
            self.assertEqual(result["state"]["status"], "ready")
            self.assertEqual(result["state"]["stage"], "fuzzing")
            archive = Path(result["false_positive_archive"])
            self.assertTrue((archive / timeout.name).is_file())
            self.assertTrue((archive / empty_leak.name).is_file())

    def test_probe_finding_uses_the_same_reproduction_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, job_id, job_dir = self._fixture(Path(directory), crash=True)
            state_path = job_dir / "state.json"
            state = json.loads(state_path.read_text())
            state["triage_artifact"] = "probe-run.json"
            state_path.write_text(json.dumps(state))
            artifacts = job_dir / "artifacts"
            (artifacts / "fuzz-run.json").replace(artifacts / "probe-run.json")
            with patch.object(runner, "_minimize", return_value=None), patch.object(
                runner, "_reproduce", return_value=(1, ASAN_LOG)
            ):
                result = runner.triage(job_id, use_ai=False)

            self.assertEqual(result["validated_group_count"], 1)
            self.assertEqual(result["state"]["status"], "validation_pending")

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
