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
            "signals": ["standard_build:cmakelists.txt", "existing_fuzz_assets:2"],
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
            state_path = job_dir / "state.json"
            state = json.loads(state_path.read_text())
            state["finding_source"] = "probe"
            state["triage_artifact"] = "probe-run.json"
            state_path.write_text(json.dumps(state))
            value = job_status(directory, job_dir.name)
            self.assertEqual(value["fuzz_percent"], 50.0)
            self.assertTrue(value["coverage_stalled"])
            self.assertEqual(value["preflight_target"], "fuzz_parser")
            self.assertEqual(value["preflight_findings"], 1)
            self.assertEqual(value["finding_source"], "probe")
            self.assertEqual(value["triage_artifact"], "probe-run.json")

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
            strict = {**CONFIG, "allow_generic_integrations": False}
            unsupported = prepare_jobs(
                [candidate()], directory, strict, LOCK, {}
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

    def test_missing_oss_fuzz_project_uses_generated_private_integration(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = prepare_jobs([candidate()], directory, CONFIG, LOCK, {})
            self.assertEqual(summary.created, 1)
            job = json.loads(next(Path(directory).glob("*/job.json")).read_text())
            self.assertEqual(job["route"]["name"], "oss_fuzz_generated")
            self.assertEqual(
                job["compatibility"]["strategy"],
                "generated_private_oss_fuzz_project",
            )
            self.assertEqual(job["compatibility"]["generic_build_signal"], "cmake")

    def test_arm64_native_mode_ignores_amd64_oss_fuzz_project(self):
        with tempfile.TemporaryDirectory() as directory:
            arm_config = {
                **CONFIG,
                "architecture": {
                    "mode": "native_only",
                    "host_arch": "aarch64",
                    "require_explicit_support": True,
                    "native_builder_image": "ubuntu:24.04",
                },
            }
            value = candidate()
            value["architecture"] = {
                "host_arch": "aarch64",
                "compatible": True,
                "confidence": 90,
                "evidence": ["ci: linux/arm64"],
                "blockers": [],
            }
            summary = prepare_jobs(
                [value],
                directory,
                arm_config,
                LOCK,
                {"org/parser": {"project": "parser", "language": "c++"}},
            )
            self.assertEqual(summary.created, 1)
            job = json.loads(next(Path(directory).glob("*/job.json")).read_text())
            self.assertEqual(job["route"]["name"], "native_generated")
            self.assertEqual(
                job["compatibility"]["strategy"], "native_generated_project"
            )
            self.assertFalse(job["execution"]["emulation_allowed"])
            required = {item["name"] for item in job["route"]["required_tools"]}
            self.assertEqual(required, {"oss-fuzz-gen", "quartetfuzz"})

    def test_native_mode_rejects_candidate_for_another_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            arm_config = {
                **CONFIG,
                "architecture": {
                    "mode": "native_only",
                    "host_arch": "aarch64",
                    "require_explicit_support": True,
                },
            }
            value = candidate()
            value["architecture"] = {
                "host_arch": "x86_64",
                "compatible": True,
                "evidence": ["ci: amd64"],
            }
            summary = prepare_jobs([value], directory, arm_config, LOCK, {})
            self.assertEqual(summary.created, 0)
            self.assertEqual(
                summary.skip_reasons, {"candidate_architecture_mismatch": 1}
            )

    def test_generic_candidate_without_supported_build_signal_is_rejected_early(self):
        with tempfile.TemporaryDirectory() as directory:
            value = candidate()
            value["assessment"]["signals"] = ["existing_fuzz_assets:2"]
            summary = prepare_jobs([value], directory, CONFIG, LOCK, {})
            self.assertEqual(summary.created, 0)
            self.assertEqual(
                summary.skip_reasons, {"no_supported_generic_build_signal": 1}
            )

    def test_supported_candidate_is_planned_before_generic_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            generic = candidate(commit="c" * 40)
            generic["repository"] = "org/generic"
            generic["repository_url"] = "https://github.com/org/generic"
            generic["assessment"]["fuzz_score"] = 100
            supported = candidate(commit="d" * 40)
            supported["assessment"]["fuzz_score"] = 1
            summary = prepare_jobs(
                [generic, supported], directory, CONFIG, LOCK,
                {"org/parser": {"project": "parser", "language": "c++"}},
                limit=1,
            )
            self.assertEqual(summary.job_ids, ["org-parser-" + "d" * 12])


if __name__ == "__main__":
    unittest.main()
