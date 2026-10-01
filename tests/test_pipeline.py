import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.pipeline import (
    PipelineError,
    job_status,
    load_oss_fuzz_support_index,
    prepare_jobs,
    quarantine_repository_cooldown_jobs,
    repository_discovery_exclusions,
    repository_failure_cooldowns,
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
    "ai_model": "gpt-6-astra",
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
    @staticmethod
    def _running_fuzz_job(directory: str) -> Path:
        prepare_jobs(
            [candidate()],
            directory,
            CONFIG,
            LOCK,
            {"org/parser": {"project": "parser", "language": "c++"}},
        )
        job_dir = next(Path(directory).glob("org-parser-*"))
        state_path = job_dir / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state.update(
            {
                "stage": "fuzzing",
                "status": "running",
                "active_fuzz_session_id": "fuzz-active",
                "active_fuzz_session_started_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            }
        )
        state_path.write_text(json.dumps(state), encoding="utf-8")
        (job_dir / "artifacts" / "coverage-plan.json").write_text(
            json.dumps({"review": {"selected_fuzz_target": "fuzz_parser"}}),
            encoding="utf-8",
        )
        return job_dir

    def test_job_status_reads_current_worker_logs_and_host_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            job_dir = self._running_fuzz_job(directory)
            artifacts = job_dir / "artifacts"
            (artifacts / "fuzz-progress.json").write_text(
                json.dumps({"completed_seconds": 3600}), encoding="utf-8"
            )
            (artifacts / "fuzz-run.json").write_text(
                json.dumps(
                    {
                        "fuzz_target": "previous_target",
                        "worker_stats": [
                            {
                                "average_exec_per_sec": 3,
                                "coverage_edges": 13,
                                "coverage_features": 30,
                            }
                        ],
                        "corpus_files": 99,
                        "crash_files": ["previous"],
                    }
                ),
                encoding="utf-8",
            )
            runtime = job_dir / "runtime-out" / "fuzz"
            runtime.mkdir(parents=True)
            (runtime / "fuzz-0.log").write_text(
                "#1 NEW cov: 10 ft: 20 corp: 1/1b exec/s: 100 rss: 10Mb\n"
                "#2 NEW cov: 12 ft: 22 corp: 2/2b exec/s: 95 rss: 10Mb\n",
                encoding="utf-8",
            )
            (runtime / "fuzz-1.log").write_text(
                "#3 pulse cov: 15 ft: 25 corp: 3/3b exec/s: 105 rss: 10Mb\n",
                encoding="utf-8",
            )
            corpus = job_dir / "corpus" / "fuzz_parser"
            crashes = job_dir / "crashes" / "fuzz_parser"
            corpus.mkdir()
            crashes.mkdir()
            (corpus / "a").write_bytes(b"a")
            (corpus / "b").write_bytes(b"b")
            (corpus / "linked").symlink_to(Path(directory) / "outside")
            (crashes / "crash-a").write_bytes(b"crash")
            (crashes / "linked").symlink_to(Path(directory) / "outside")

            value = job_status(directory, job_dir.name)
            self.assertEqual(value["fuzz_target"], "fuzz_parser")
            self.assertEqual(value["fuzz_completed_seconds"], 3600)
            self.assertEqual(value["exec_per_second"], 200)
            self.assertEqual(value["coverage_edges"], 15)
            self.assertEqual(value["coverage_features"], 30)
            self.assertEqual(value["corpus_files"], 2)
            self.assertEqual(value["crash_files"], 1)
            self.assertEqual(value["total_crashes"], 1)
            self.assertIsNotNone(value["live_metrics_updated_at"])
            self.assertFalse(value["live_metrics_truncated"])

    def test_job_status_ignores_stale_logs_and_stops_live_reads_when_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            job_dir = self._running_fuzz_job(directory)
            (job_dir / "artifacts" / "fuzz-run.json").write_text(
                json.dumps(
                    {
                        "worker_stats": [
                            {
                                "average_exec_per_sec": 7,
                                "coverage_edges": 8,
                                "coverage_features": 9,
                            }
                        ],
                        "corpus_files": 4,
                        "crash_files": [],
                    }
                ),
                encoding="utf-8",
            )
            runtime = job_dir / "runtime-out" / "fuzz"
            runtime.mkdir(parents=True)
            log = runtime / "fuzz-0.log"
            log.write_text(
                "#1 NEW cov: 100 ft: 200 corp: 1/1b exec/s: 999\n",
                encoding="utf-8",
            )
            state_path = job_dir / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            old = datetime.fromisoformat(
                state["active_fuzz_session_started_at"]
            ).timestamp() - 30
            os.utime(log, (old, old))
            corpus = job_dir / "corpus" / "fuzz_parser"
            corpus.mkdir()
            (corpus / "current").write_bytes(b"current")

            running = job_status(directory, job_dir.name)
            self.assertEqual(running["exec_per_second"], 7)
            self.assertEqual(running["coverage_edges"], 8)
            self.assertEqual(running["coverage_features"], 9)
            self.assertEqual(running["corpus_files"], 1)
            self.assertIsNone(running["live_metrics_updated_at"])

            os.utime(log, None)
            state["status"] = "ready"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            ready = job_status(directory, job_dir.name)
            self.assertEqual(ready["exec_per_second"], 7)
            self.assertEqual(ready["corpus_files"], 4)
            self.assertIsNone(ready["live_metrics_updated_at"])

    def test_job_status_does_not_follow_live_metric_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            job_dir = self._running_fuzz_job(directory)
            external = Path(directory) / "external"
            external.mkdir()
            (external / "fuzz-0.log").write_text(
                "#1 NEW cov: 999 ft: 999 corp: 1/1b exec/s: 999\n",
                encoding="utf-8",
            )
            (external / "item").write_bytes(b"external")
            runtime_root = job_dir / "runtime-out"
            runtime_root.mkdir()
            (runtime_root / "fuzz").symlink_to(external, target_is_directory=True)
            (job_dir / "corpus" / "fuzz_parser").symlink_to(
                external, target_is_directory=True
            )
            value = job_status(directory, job_dir.name)
            self.assertEqual(value["exec_per_second"], 0)
            self.assertEqual(value["coverage_edges"], 0)
            self.assertEqual(value["corpus_files"], 0)

            (runtime_root / "fuzz").unlink()
            runtime = runtime_root / "fuzz"
            runtime.mkdir()
            (runtime / "fuzz-0.log").symlink_to(external / "fuzz-0.log")
            (runtime / "fuzz-64.log").write_text(
                "#1 NEW cov: 888 ft: 888 corp: 1/1b exec/s: 888\n",
                encoding="utf-8",
            )
            (runtime / "fuzz-other.log").write_text(
                "#1 NEW cov: 777 ft: 777 corp: 1/1b exec/s: 777\n",
                encoding="utf-8",
            )
            self.assertEqual(job_status(directory, job_dir.name)["exec_per_second"], 0)

    def test_job_status_reads_only_the_recent_log_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            job_dir = self._running_fuzz_job(directory)
            runtime = job_dir / "runtime-out" / "fuzz"
            runtime.mkdir(parents=True)
            log = runtime / "fuzz-0.log"
            log.write_text(
                "#1 NEW cov: 999 ft: 999 corp: 1/1b exec/s: 999\n"
                + ("x" * 70_000),
                encoding="utf-8",
            )
            self.assertEqual(job_status(directory, job_dir.name)["exec_per_second"], 0)

            with log.open("a", encoding="utf-8") as handle:
                handle.write(
                    "\n#2 NEW cov: 10 ft: 20 corp: 2/2b exec/s: 42\n"
                )
            self.assertEqual(job_status(directory, job_dir.name)["exec_per_second"], 42)

    def test_job_status_marks_bounded_corpus_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            job_dir = self._running_fuzz_job(directory)
            corpus = job_dir / "corpus" / "fuzz_parser"
            corpus.mkdir()
            for name in ("a", "b", "c"):
                (corpus / name).write_bytes(b"x")
            with patch("fuzz_target_scout.pipeline._LIVE_FILE_LIMIT", 2):
                value = job_status(directory, job_dir.name)
            self.assertEqual(value["corpus_files"], 2)
            self.assertTrue(value["live_metrics_truncated"])

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

    def test_planning_does_not_queue_a_new_commit_for_the_same_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            first = prepare_jobs([candidate(commit="b" * 40)], directory, CONFIG, LOCK)
            second = prepare_jobs([candidate(commit="c" * 40)], directory, CONFIG, LOCK)

            self.assertEqual(first.created, 1)
            self.assertEqual(second.created, 0)
            self.assertEqual(
                second.skip_reasons, {"repository_already_planned": 1}
            )

    def test_completed_job_allows_a_new_pinned_commit_for_same_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            first = prepare_jobs([candidate(commit="b" * 40)], directory, CONFIG, LOCK)
            first_job = Path(directory) / first.job_ids[0]
            state_path = first_job / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state.update({"stage": "complete", "status": "skipped_after_recovery"})
            state_path.write_text(json.dumps(state), encoding="utf-8")

            second = prepare_jobs(
                [candidate(commit="c" * 40)], directory, CONFIG, LOCK
            )
            same_commit = prepare_jobs(
                [candidate(commit="b" * 40)], directory, CONFIG, LOCK
            )

            self.assertEqual(second.created, 1)
            self.assertEqual(same_commit.created, 0)
            self.assertEqual(same_commit.existing, 0)
            self.assertEqual(same_commit.job_ids, [])
            self.assertEqual(
                same_commit.skip_reasons, {"historical_exact_commit": 1}
            )
            self.assertEqual(len(list(Path(directory).glob("*/job.json"))), 2)

    def test_terminal_exact_commits_do_not_consume_new_job_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def named(repository: str):
                value = candidate()
                value["repository"] = repository
                value["repository_url"] = f"https://github.com/{repository}"
                value["policy"]["security_url"] = (
                    f"https://github.com/{repository}/security/policy"
                )
                return value

            old_a = named("org/aa-old")
            old_b = named("org/ab-old")
            fresh = named("org/zz-fresh")
            for value in (old_a, old_b):
                created = prepare_jobs([value], root, CONFIG, LOCK)
                self._complete_job(root / created.job_ids[0], "skipped_after_recovery")

            summary = prepare_jobs(
                [old_a, old_b, fresh], root, CONFIG, LOCK, limit=1
            )
            self.assertEqual(summary.created, 1)
            self.assertEqual(summary.existing, 0)
            self.assertEqual(summary.skip_reasons, {"historical_exact_commit": 2})
            self.assertEqual(summary.job_ids, ["org-zz-fresh-" + "b" * 12])
            self.assertEqual(len(list(root.glob("*/job.json"))), 3)

            another = named("org/zzz-another")
            followup = prepare_jobs([fresh, another], root, CONFIG, LOCK, limit=1)
            self.assertEqual(followup.created, 0)
            self.assertEqual(followup.existing, 1)
            self.assertEqual(followup.job_ids, summary.job_ids)

    def test_repeated_repository_failures_open_a_planning_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {
                **CONFIG,
                "repository_failure_threshold": 2,
                "repository_failure_cooldown_hours": 168,
            }
            first = prepare_jobs([candidate(commit="b" * 40)], directory, config, LOCK)
            self._complete_job(Path(directory) / first.job_ids[0], "skipped_after_recovery")
            second = prepare_jobs([candidate(commit="c" * 40)], directory, config, LOCK)
            self._complete_job(Path(directory) / second.job_ids[0], "skipped_after_recovery")
            third = prepare_jobs([candidate(commit="d" * 40)], directory, config, LOCK)

            self.assertEqual(third.created, 0)
            self.assertEqual(
                third.skip_reasons, {"repository_failure_cooldown": 1}
            )

    def test_offline_dependency_opens_finite_cooldown_after_one_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {
                **CONFIG,
                "repository_failure_threshold": 2,
                "repository_failure_cooldown_hours": 168,
            }
            root = Path(directory)
            first = prepare_jobs([candidate(commit="b" * 40)], root, config, LOCK)
            job = root / first.job_ids[0]
            self._complete_job(job, "unsupported_integration")
            state_path = job / "state.json"
            state = json.loads(state_path.read_text())
            state["failure_reason"] = "offline_external_dependency"
            state_path.write_text(json.dumps(state))
            next_commit = prepare_jobs(
                [candidate(commit="c" * 40)], root, config, LOCK
            )

            self.assertEqual(next_commit.created, 0)
            self.assertEqual(
                next_commit.skip_reasons, {"repository_failure_cooldown": 1}
            )
            self.assertIn(
                "org/parser", repository_discovery_exclusions(root, config)
            )
            expired = datetime.fromisoformat(state["updated_at"]) + timedelta(
                hours=169
            )
            self.assertNotIn(
                "org/parser",
                repository_failure_cooldowns(root, config, now=expired),
            )

    def test_discovery_exclusions_combine_live_and_success_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {**CONFIG, "repository_success_cooldown_hours": 168}
            root_path = Path(directory)
            first = prepare_jobs([candidate(commit="b" * 40)], root_path, config, LOCK)
            self._complete_job(root_path / first.job_ids[0], "exhausted")
            live = candidate(commit="c" * 40)
            live["repository"] = "org/live"
            live["repository_url"] = "https://github.com/org/live"
            prepare_jobs([live], root_path, config, LOCK)
            self.assertEqual(
                repository_discovery_exclusions(root_path, config),
                {"org/parser", "org/live"},
            )

    def test_recent_success_opens_a_repository_diversity_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {**CONFIG, "repository_success_cooldown_hours": 168}
            first = prepare_jobs([candidate(commit="b" * 40)], directory, config, LOCK)
            self._complete_job(Path(directory) / first.job_ids[0], "exhausted")
            second = prepare_jobs([candidate(commit="c" * 40)], directory, config, LOCK)
            self.assertEqual(second.created, 0)
            self.assertEqual(second.skip_reasons, {"repository_success_cooldown": 1})

    def test_successful_repository_run_resets_failure_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {
                **CONFIG,
                "repository_failure_threshold": 2,
                "repository_failure_cooldown_hours": 168,
            }
            first = prepare_jobs([candidate(commit="b" * 40)], directory, config, LOCK)
            self._complete_job(Path(directory) / first.job_ids[0], "skipped_after_recovery")
            second = prepare_jobs([candidate(commit="c" * 40)], directory, config, LOCK)
            self._complete_job(Path(directory) / second.job_ids[0], "exhausted")
            third = prepare_jobs([candidate(commit="d" * 40)], directory, config, LOCK)

            self.assertEqual(third.created, 1)

    def test_queued_job_is_quarantined_when_repository_circuit_opens(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {
                **CONFIG,
                "repository_failure_threshold": 2,
                "repository_failure_cooldown_hours": 168,
            }
            root = Path(directory)
            first = prepare_jobs([candidate(commit="b" * 40)], root, config, LOCK)
            self._complete_job(root / first.job_ids[0], "skipped_after_recovery")
            second = prepare_jobs([candidate(commit="c" * 40)], root, config, LOCK)
            queued = root / second.job_ids[0]
            third = root / ("org-parser-" + "d" * 12)
            third.mkdir()
            (third / "job.json").write_text(json.dumps({
                "source": {"repository": "org/parser", "commit": "d" * 40}
            }))
            (third / "state.json").write_text(json.dumps({
                "job_id": third.name,
                "stage": "policy_recheck",
                "status": "queued",
                "updated_at": "2026-09-27T00:00:00+00:00",
            }))
            self._complete_job(queued, "skipped_after_recovery")

            quarantined = quarantine_repository_cooldown_jobs(root, config)
            state = json.loads((third / "state.json").read_text())
            self.assertEqual(quarantined, [third.name])
            self.assertEqual(state["stage"], "complete")
            self.assertEqual(state["status"], "skipped_repository_cooldown")

    @staticmethod
    def _complete_job(job: Path, status: str) -> None:
        state_path = job / "state.json"
        state = json.loads(state_path.read_text())
        state.update({"stage": "complete", "status": status})
        state_path.write_text(json.dumps(state), encoding="utf-8")

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
