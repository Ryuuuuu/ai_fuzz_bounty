import fcntl
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.generic_integration import _select_public_candidate
from fuzz_target_scout.pipeline import PipelineError
from fuzz_target_scout.retarget import retarget_native_job
import fuzz_target_scout.retarget as retarget_module


class RetargetNativeJobTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runs = self.root / "runs"
        self.job_id = "org-parser-aaaaaaaaaaaa"
        self.job = self.runs / self.job_id
        self.job.mkdir(parents=True)
        self.config = {
            "pipeline": {"runs_path": str(self.runs)},
            "agent": {"state_path": str(self.root / "central" / "state.json")},
        }
        source = self.job / "source"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        (source / "api.h").write_text("int old_api();\n")
        subprocess.run(["git", "-C", str(source), "add", "api.h"], check=True)
        subprocess.run([
            "git", "-C", str(source), "-c", "user.name=Test",
            "-c", "user.email=test@example.invalid", "commit", "-qm", "init",
        ], check=True)
        commit = subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True,
        ).strip()
        subprocess.run([
            "git", "-C", str(source), "worktree", "add", "--detach",
            str(self.job / "build-source"), commit,
        ], check=True, capture_output=True)
        self._json(self.job / "job.json", {
            "job_id": self.job_id, "created_at": "2026-01-01T00:00:00Z",
            "route": {"name": "native_generated"}, "source": {"commit": commit},
        })
        self._json(self.job / "state.json", {
            "schema_version": 2, "job_id": self.job_id, "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z", "stage": "fuzzing",
            "status": "interrupted", "last_error": "old failure",
            "fuzz_completed_seconds": 3600, "coverage_stalled": True,
            "active_fuzz_container": "stale-old-container", "attempts": {"worker_failures": 2},
        })
        self.artifacts = self.job / "artifacts"
        self._json(self.artifacts / "generic-integration.json", {
            "harness_origin": "codex_oss_fuzz_gen_adapter",
            "candidate": {"id": "old-candidate", "file": "include/old.h", "signature": "void refresh();"},
        })
        for name in (
            "integration-manifest.json", "build-manifest.json", "probe-run.json",
            "quartet-review.json", "coverage-plan.json", "fuzz-progress.json",
        ):
            self._json(self.artifacts / name, {"old": True})
        for name in (
            "source-checkout.json", "toolchain.json", "authorization-recheck.json",
            "central-recovery.json",
        ):
            self._json(self.artifacts / name, {"preserve": True})
        for directory, name in (
            ("integration/native", "generic_harness.cc"),
            ("build-output", "old-fuzzer"), ("corpus/generic_fuzzer", "old-seed"),
            ("logs", "fuzz.log"), ("runtime-out", "run.txt"),
        ):
            path = self.job / directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("old evidence")

    @staticmethod
    def _json(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def _retarget(self, **kwargs):
        with patch("fuzz_target_scout.retarget._check_running_container"):
            return retarget_native_job(
                self.config, self.job_id, "Old harness ignores fuzz bytes", **kwargs
            )

    def _failed_generation(self):
        (self.artifacts / "generic-integration.json").unlink()
        generation = self.artifacts / "generic-integration-generation"
        generation.mkdir()
        (generation / "prompt.txt").write_text("Generate a harness", encoding="utf-8")
        (generation / "01.rawoutput").write_text("wrong harness", encoding="utf-8")
        (generation / "adapter.log").write_text("adapter finished", encoding="utf-8")
        state_path = self.job / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state.update(stage="complete", status="skipped_after_recovery",
                     last_error="generated harness does not reference the selected target symbol")
        self._json(state_path, state)
        return generation

    def test_archive_and_reset_same_job(self):
        result = self._retarget()
        archive = self.job / result["archive"]
        state = json.loads((self.job / "state.json").read_text())
        exclusions = json.loads((self.artifacts / "harness-exclusions.json").read_text())
        self.assertTrue((archive / "state.json").is_file())
        self.assertTrue((archive / "artifacts" / "generic-integration.json").is_file())
        self.assertTrue((archive / "artifacts" / "coverage-plan.json").is_file())
        self.assertTrue((archive / "integration" / "native" / "generic_harness.cc").is_file())
        self.assertTrue((archive / "corpus" / "generic_fuzzer" / "old-seed").is_file())
        self.assertTrue((archive / "logs" / "fuzz.log").is_file())
        self.assertTrue((self.job / "build-source" / "api.h").is_file())
        self.assertEqual(state["stage"], "integration")
        self.assertEqual(state["status"], "prepared")
        self.assertNotIn("active_fuzz_container", state)
        self.assertNotIn("fuzz_completed_seconds", state)
        self.assertEqual(exclusions["candidate_ids"], ["old-candidate"])
        for name in (
            "source-checkout.json", "toolchain.json", "authorization-recheck.json",
            "central-recovery.json",
        ):
            self.assertTrue((self.artifacts / name).is_file())

    def test_failed_generation_without_integration_record_requeues_same_job(self):
        self._failed_generation()
        result = self._retarget()
        archive = self.job / result["archive"]
        state = json.loads((self.job / "state.json").read_text(encoding="utf-8"))
        archived_state = json.loads((archive / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(result["job_id"], self.job_id)
        self.assertEqual(result["previous_candidate"], {})
        self.assertEqual((state["stage"], state["status"]), ("integration", "prepared"))
        self.assertEqual(state["attempts"], {"retargets": 1})
        self.assertEqual(archived_state["status"], "skipped_after_recovery")
        self.assertTrue((archive / "artifacts" / "generic-integration-generation" / "prompt.txt").is_file())
        self.assertTrue((archive / "artifacts" / "generic-integration-generation" / "01.rawoutput").is_file())
        self.assertTrue((archive / "artifacts" / "generic-integration-generation" / "adapter.log").is_file())
        self.assertTrue((self.artifacts / "central-recovery.json").is_file())
        self.assertTrue((self.job / "build-source" / "api.h").is_file())
        self.assertFalse((self.artifacts / "generic-integration.json").exists())
        with self.assertRaisesRegex(PipelineError, "no generated harness integration"):
            self._retarget()

    def test_missing_generation_evidence_refuses_retarget(self):
        generation = self._failed_generation()
        (generation / "01.rawoutput").unlink()
        (generation / "adapter.log").unlink()
        with self.assertRaisesRegex(PipelineError, "failed generation evidence"):
            self._retarget()
        (generation / "adapter.log").write_text("adapter failed", encoding="utf-8")
        (generation / "prompt.txt").unlink()
        with self.assertRaisesRegex(PipelineError, "failed generation evidence"):
            self._retarget()
        self.assertEqual(json.loads((self.job / "state.json").read_text())["status"], "skipped_after_recovery")

    def test_failed_generation_requires_terminal_recovery_state(self):
        self._failed_generation()
        state_path = self.job / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        for stage, status, error in (
            ("integration", "prepared", state["last_error"]),
            ("complete", "exhausted", state["last_error"]),
            ("integration", "skipped_after_recovery", state["last_error"]),
            ("complete", "skipped_after_recovery", None),
        ):
            with self.subTest(stage=stage, status=status, error=error):
                state.update(stage=stage, status=status, last_error=error)
                self._json(state_path, state)
                with self.assertRaisesRegex(PipelineError, "failed generation evidence"):
                    self._retarget()
        self.assertFalse((self.artifacts / "history").exists())

    def test_failed_generation_still_checks_findings_and_pinned_source(self):
        self._failed_generation()
        finding = self.artifacts / "bug-bounty-report-draft.md"
        finding.write_text("draft", encoding="utf-8")
        with self.assertRaisesRegex(PipelineError, "retarget refused"):
            self._retarget()
        finding.unlink()
        (self.job / "build-source" / "api.h").write_text("changed\n")
        with self.assertRaisesRegex(PipelineError, "uncommitted changes"):
            self._retarget()

    def test_dry_run_does_not_change_evidence(self):
        result = self._retarget(dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertEqual(json.loads((self.job / "state.json").read_text())["stage"], "fuzzing")
        self.assertTrue((self.artifacts / "generic-integration.json").is_file())
        self.assertFalse((self.artifacts / "history").exists())

    def test_worker_lock_refuses_retarget(self):
        lock_path = self.runs / ".pipeline-worker.lock"
        with lock_path.open("w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(PipelineError, "worker is active"):
                self._retarget()
        self.assertTrue((self.artifacts / "generic-integration.json").is_file())

    def test_running_container_refuses_retarget(self):
        with patch(
            "fuzz_target_scout.retarget._check_running_container",
            side_effect=PipelineError("job has a running Docker container"),
        ):
            with self.assertRaisesRegex(PipelineError, "running Docker container"):
                retarget_native_job(self.config, self.job_id, "Shallow harness")
        self.assertTrue((self.artifacts / "generic-integration.json").is_file())

    def test_central_service_lock_refuses_retarget(self):
        lock_path = self.root / "central" / ".central-agent.lock"
        lock_path.parent.mkdir()
        with lock_path.open("w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(PipelineError, "central fuzz service is active"):
                self._retarget()
        self.assertTrue((self.artifacts / "generic-integration.json").is_file())

    def test_docker_check_matches_job_container_and_fails_closed(self):
        with patch("fuzz_target_scout.retarget.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = f"fts-{self.job_id}-fuzz-abc\nother-container\n"
            with self.assertRaisesRegex(PipelineError, "running Docker container"):
                retarget_module._check_running_container(self.job_id)
            run.return_value.stdout = "unrelated-job-fuzz-abc\n"
            with self.assertRaisesRegex(PipelineError, "running Docker container"):
                retarget_module._check_running_container(self.job_id)
            run.return_value.returncode = 1
            run.return_value.stderr = "daemon unavailable"
            with self.assertRaisesRegex(PipelineError, "cannot verify running Docker"):
                retarget_module._check_running_container(self.job_id)

    def test_failed_state_write_restores_old_evidence(self):
        original_write = retarget_module._write_json

        def fail_state_write(path, value):
            if path == self.job / "state.json":
                raise OSError("simulated state write failure")
            return original_write(path, value)

        with patch("fuzz_target_scout.retarget._check_running_container"):
            with patch("fuzz_target_scout.retarget._write_json", side_effect=fail_state_write):
                with self.assertRaisesRegex(OSError, "simulated state write failure"):
                    retarget_native_job(self.config, self.job_id, "Shallow harness")
        self.assertEqual(json.loads((self.job / "state.json").read_text())["stage"], "fuzzing")
        self.assertTrue((self.artifacts / "generic-integration.json").is_file())
        self.assertTrue((self.job / "integration" / "native" / "generic_harness.cc").is_file())
        self.assertTrue((self.job / "corpus" / "generic_fuzzer" / "old-seed").is_file())

    def test_dirty_build_source_refuses_retarget(self):
        (self.job / "build-source" / "api.h").write_text("changed\n")
        with self.assertRaisesRegex(PipelineError, "uncommitted changes"):
            self._retarget()
        self.assertTrue((self.artifacts / "generic-integration.json").is_file())

    def test_crash_or_report_evidence_refuses_retarget(self):
        cases = (
            self.job / "crashes" / "generic_fuzzer" / "crash-input",
            self.artifacts / "bug-bounty-report-draft.md",
            self.job / "poc" / "reproduce.sh",
        )
        for path in cases:
            with self.subTest(path=path.name):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("finding evidence")
                with self.assertRaisesRegex(PipelineError, "retarget refused"):
                    self._retarget()
                path.unlink()
        self._json(self.artifacts / "triage-summary.json", {
            "validated_group_count": 1, "groups": [{"reproduced": True}],
        })
        with self.assertRaisesRegex(PipelineError, "reproduced finding"):
            self._retarget()
        self.assertTrue((self.artifacts / "generic-integration.json").is_file())

    def test_selector_honors_candidate_id_exclusion(self):
        source = self.root / "selector"
        source.mkdir()
        (source / "api.h").write_text(
            "class Parser {\npublic:\n  int parse(std::string input);\n"
            "  int parse_bytes(const uint8_t* input, size_t size);\n};\n"
        )
        chosen = _select_public_candidate(source)
        alternate = _select_public_candidate(source, {chosen["id"]})
        self.assertNotEqual(chosen["id"], alternate["id"])


if __name__ == "__main__":
    unittest.main()
