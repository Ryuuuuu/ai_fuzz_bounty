import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.pipeline import PipelineError
from fuzz_target_scout.validation_agent import ValidationAgentRunner, _source_excerpts


class ValidationAgentTests(unittest.TestCase):
    def test_creates_local_poc_and_finishes_for_human_review(self):
        with tempfile.TemporaryDirectory() as directory:
            runner, job_id, job = self._fixture(Path(directory))
            review = {
                "findings": [
                    {
                        "group_id": "0123456789abcdef",
                        "title": "Parser heap overflow",
                        "summary": "A stable ASan failure occurs in parse.",
                        "trigger_path": ["LLVMFuzzerTestOneInput", "parse"],
                        "reproduction_steps": ["Run the generated local script."],
                        "impact_assessment": "Out-of-bounds memory access in the parser.",
                        "impact_evidence": ["ASan heap-buffer-overflow"],
                        "confidence": "high",
                        "uncertainties": ["External reachability was not assessed."],
                        "duplicate_search_queries": ["parser heap buffer overflow"],
                    }
                ]
            }
            with patch(
                "fuzz_target_scout.validation_agent.CodexValidationReviewer.review",
                return_value=(review, {"input_tokens": 10, "cached_tokens": 5, "output_tokens": 2}),
            ):
                result = runner.validate(job_id)
            self.assertEqual(result["state"]["status"], "ready_for_human")
            self.assertEqual(result["state"]["stage"], "complete")
            script = Path(result["poc_artifacts"][0]["script_path"])
            self.assertTrue(script.is_file())
            self.assertIn("--network none", script.read_text())
            self.assertTrue((job / "artifacts" / "bug-bounty-report-draft.md").is_file())

    def test_rejects_minimized_input_outside_job(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner, job_id, job = self._fixture(root)
            outside = root / "outside"
            outside.write_bytes(b"bad")
            triage_path = job / "artifacts" / "triage-summary.json"
            triage = json.loads(triage_path.read_text())
            triage["groups"][0]["representative"]["minimal_path"] = str(outside)
            triage_path.write_text(json.dumps(triage))
            with self.assertRaisesRegex(PipelineError, "minimized input"):
                runner.validate(job_id)

    def test_source_excerpt_rejects_parent_symlink_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            outside = root / "outside"
            source.mkdir()
            outside.mkdir()
            (outside / "secret.cc").write_text("void secret() {}\n")
            try:
                (source / "linked").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlinks are unavailable: {exc}")
            groups = [{"stack_frames": ["secret /src/linked/secret.cc:1:1"]}]
            self.assertEqual(_source_excerpts(source, groups), [])

    @staticmethod
    def _fixture(root: Path):
        job_id = "org-parser-aaaaaaaaaaaa"
        job = root / job_id
        artifacts = job / "artifacts"
        validation = job / "validation" / ("b" * 64)
        output = job / "build-output" / "asan"
        source = job / "source"
        for path in (artifacts, validation, output, source):
            path.mkdir(parents=True, exist_ok=True)
        minimal = validation / "minimized"
        minimal.write_bytes(b"bad")
        (output / "fuzz_parser").write_bytes(b"binary")
        (source / "parser.cc").write_text("void parse() {}\n")
        representative = {
            "minimal_path": str(minimal),
            "minimal_sha256": "c" * 64,
            "minimal_size": 3,
            "reproduction_attempts": [
                {"stack_frames": ["parse /src/parser.cc:1:1"]},
                {"stack_frames": ["parse /src/parser.cc:1:1"]},
                {"stack_frames": ["parse /src/parser.cc:1:1"]},
            ],
        }
        group = {
            "group_id": "0123456789abcdef",
            "fingerprint": "d" * 24,
            "reproduced": True,
            "representative": representative,
            "secondary_sanitizer": {"status": "checked"},
        }
        (job / "job.json").write_text(json.dumps({
            "source": {"repository": "org/parser", "commit": "a" * 40},
            "authorization": {"program_url": "https://example.invalid/bounty"},
        }))
        (job / "state.json").write_text(json.dumps({
            "stage": "validation", "status": "validation_pending", "attempts": {}
        }))
        (artifacts / "build-manifest.json").write_text(json.dumps({
            "fuzz_targets": ["fuzz_parser"], "output_directory": str(output)
        }))
        (artifacts / "triage-summary.json").write_text(json.dumps({
            "fuzz_target": "fuzz_parser", "groups": [group]
        }))
        (artifacts / "validation-handoff.json").write_text(json.dumps({
            "fuzz_target": "fuzz_parser", "validated_groups": [group]
        }))
        config = {"pipeline": {
            "runs_path": str(root), "container_memory_mb": 1024,
            "input_timeout_seconds": 2, "ai_executable": "codex",
            "ai_model": "gpt-daybreak-blue-latest", "ai_reasoning_effort": "high",
            "validation_schema_path": str(root / "schema.json"),
            "triage_timeout_seconds": 60,
        }}
        return ValidationAgentRunner(config), job_id, job


if __name__ == "__main__":
    unittest.main()
