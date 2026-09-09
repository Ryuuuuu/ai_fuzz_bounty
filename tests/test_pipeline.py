import json
import tempfile
import unittest
from pathlib import Path

from fuzz_target_scout.pipeline import (
    PipelineError,
    job_status,
    load_oss_fuzz_support_index,
    prepare_jobs,
)


LOCK = {
    "schema_version": 1,
    "tools": {
        name: {
            "url": f"https://example.test/{name}.git",
            "commit": "a" * 40,
            "integration": name,
        }
        for name in (
            "oss-fuzz",
            "oss-fuzz-gen",
            "quartetfuzz",
            "vistafuzz",
            "aflplusplus",
            "fuzz-introspector",
        )
    },
}

CONFIG = {
    "languages": ["C", "C++"],
    "ai_model": "gpt-daybreak-blue-latest",
    "ai_reasoning_effort": "high",
    "max_harness_attempts": 3,
    "setup_timeout_seconds": 5400,
    "smoke_seconds": 300,
    "fuzz_seconds": 86400,
    "triage_timeout_seconds": 3600,
    "coverage_stall_seconds": 14400,
    "parallel_workers": 6,
}


def candidate(status="verified", language="C++", commit="b" * 40):
    return {
        "repository": "org/parser",
        "repository_url": "https://github.com/org/parser",
        "commit": commit,
        "default_branch": "main",
        "language": language,
        "policy": {
            "status": status,
            "confidence": 95,
            "source": "repository_security",
            "program_url": "https://example.test/bounty",
            "security_url": "https://github.com/org/parser/security/policy",
        },
        "assessment": {
            "suggested_entry_kind": "existing_harness",
            "signals": ["existing_fuzz_assets:2"],
        },
        "observed_at": "2026-09-09T00:00:00+00:00",
    }


class PipelineTests(unittest.TestCase):
    def test_job_status_reports_checkpoint_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            prepare_jobs(
                [candidate()],
                directory,
                CONFIG,
                LOCK,
                {"org/parser": {"project": "parser", "language": "c++"}},
            )
            job_dir = next(Path(directory).glob("org-parser-*"))
            (job_dir / "artifacts" / "fuzz-progress.json").write_text(
                json.dumps({"completed_seconds": 43200, "coverage_stalled": True})
            )
            (job_dir / "artifacts" / "probe-run.json").write_text(
                json.dumps(
                    {
                        "fuzz_target": "fuzz_parser",
                        "status": "sanitizer_finding",
                        "crash_files": ["leak-a"],
                    }
                )
            )
            value = job_status(directory, job_dir.name)
            self.assertEqual(value["fuzz_percent"], 50.0)
            self.assertTrue(value["coverage_stalled"])
            self.assertEqual(value["preflight_target"], "fuzz_parser")
            self.assertEqual(value["preflight_findings"], 1)

    def test_support_index_must_match_toolchain_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "support.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "oss_fuzz_commit": "b" * 40,
                        "projects": [],
                    }
                )
            )
            with self.assertRaises(PipelineError):
                load_oss_fuzz_support_index(path, LOCK)

    def test_only_verified_enabled_candidates_become_pinned_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = prepare_jobs(
                [candidate(), candidate(status="conditional")],
                directory,
                CONFIG,
                LOCK,
            )
            self.assertEqual(summary.created, 1)
            self.assertEqual(summary.skip_reasons, {"policy_not_verified": 1})
            job_path = next(Path(directory).glob("*/job.json"))
            job = json.loads(job_path.read_text(encoding="utf-8"))
            self.assertEqual(job["route"]["name"], "oss_fuzz_existing")
            self.assertEqual(job["budgets"]["fuzz_seconds"], 86400)
            self.assertEqual(job["ai"]["provider"], "codex_cli")
            self.assertIn("quartet_p1_logic_correctness", job["quality_gates"])
            required = {item["name"] for item in job["route"]["required_tools"]}
            self.assertEqual(required, {"oss-fuzz", "oss-fuzz-gen", "quartetfuzz"})

    def test_unpinned_and_disabled_languages_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = prepare_jobs(
                [candidate(commit=""), candidate(language="Python")],
                directory,
                CONFIG,
                LOCK,
            )
            self.assertEqual(summary.created, 0)
            self.assertEqual(summary.skip_reasons["commit_not_pinned"], 1)
            self.assertEqual(summary.skip_reasons["language_not_enabled"], 1)

    def test_planning_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            first = prepare_jobs([candidate()], directory, CONFIG, LOCK)
            second = prepare_jobs([candidate()], directory, CONFIG, LOCK)
            self.assertEqual(first.created, 1)
            self.assertEqual(second.existing, 1)
            self.assertEqual(second.created, 0)

    def test_support_index_filters_before_work_order_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            unsupported = prepare_jobs(
                [candidate()], directory, CONFIG, LOCK, {}
            )
            self.assertEqual(unsupported.created, 0)
            self.assertEqual(
                unsupported.skip_reasons, {"no_pinned_oss_fuzz_project": 1}
            )
            supported = prepare_jobs(
                [candidate()],
                directory,
                CONFIG,
                LOCK,
                {"org/parser": {"project": "parser", "language": "c++"}},
            )
            self.assertEqual(supported.created, 1)
            job = json.loads(next(Path(directory).glob("*/job.json")).read_text())
            self.assertEqual(job["compatibility"]["oss_fuzz_project"], "parser")


if __name__ == "__main__":
    unittest.main()
