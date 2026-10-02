import fcntl
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.harness_repair import repair_native_harness
from fuzz_target_scout.pipeline import PipelineError
import fuzz_target_scout.harness_repair as repair_module


OLD = (
    '#include <cstddef>\n#include <cstdint>\n'
    'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) '
    '{ parse_data(data, size); return 0; }\n'
)
NEW = (
    '#include <cstddef>\n#include <cstdint>\n'
    'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) '
    '{ if (size) parse_data(data, size); return 0; }\n'
)


class HarnessRepairTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
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
        (source / "api.h").write_text(
            "#include <cstdint>\n#include <cstddef>\n"
            "int parse_data(const uint8_t*, size_t);\n"
        )
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
            "schema_version": 2, "job_id": self.job_id,
            "created_at": "2026-01-01T00:00:00Z",
            "stage": "quartet_gate", "status": "quartet_review_required",
            "last_error": "old failure", "fuzz_completed_seconds": 300,
            "active_fuzz_container": "old-container",
            "attempts": {"quartet_repair": 3, "worker_failures": 4},
        })
        self.artifacts = self.job / "artifacts"
        self.artifacts.mkdir()
        digest = hashlib.sha256(OLD.encode()).hexdigest()
        self._json(self.artifacts / "generic-integration.json", {
            "candidate": {
                "id": "api", "file": "api.h",
                "signature": "int parse_data(const uint8_t*, size_t)",
            },
            "harness_origin": "codex_oss_fuzz_gen_adapter",
            "harness_sha256": digest,
            "repair_attempts": [],
        })
        project = self.job / "integration" / "native"
        project.mkdir(parents=True)
        (project / "generic_harness.cc").write_text(OLD)
        (project / "build.sh").write_text("#!/bin/sh\n")
        self._json(self.artifacts / "integration-manifest.json", {
            "route": "native_generated", "target_commit": commit,
            "native_project_directory": str(project),
            "integration_file_sha256": {
                "generic_harness.cc": digest, "build.sh": "old-build-hash",
            },
            "runner_image": "stale-image",
        })
        self._json(self.artifacts / "quartet-review.json", {
            "facts": {"dynamic_evidence": {
                "crash_diagnostics": {"kind": "uncaught_cpp_exception", "lines": ["exception"]}
            }}
        })
        for name in (
            "build-manifest.json", "smoke.json", "probe-run.json",
            "coverage-plan.json", "fuzz-progress.json",
        ):
            self._json(self.artifacts / name, {"old": True})
        for name in (
            "source-checkout.json", "toolchain.json", "authorization-recheck.json",
            "central-recovery.json", "integration-support.json",
        ):
            self._json(self.artifacts / name, {"preserve": True})
        for directory, name, data in (
            ("corpus/generic_fuzzer", "seed", b"abc"),
            ("crashes/generic_fuzzer", "crash", b"crash"),
            ("logs", "native-build.log", b"old log"),
            ("runtime-out", "run.txt", b"old runtime"),
            ("build-output/asan", "generic_fuzzer", b"binary"),
            ("native-work", "cache", b"old cache"),
            ("native-out", "generic_fuzzer", b"old binary"),
        ):
            path = self.job / directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        probe_log = self.job / "logs" / "probe-generic_fuzzer.log"
        probe_log.write_text(
            "terminate called after throwing an instance of 'std::runtime_error'\n",
            encoding="utf-8",
        )
        self._json(self.artifacts / "probe-run.json", {
            "status": "sanitizer_finding",
            "crash_files": ["crash"],
            "log_path": str(probe_log),
        })
        self.replacement = self.root / "replacement.cc"
        self.replacement.write_text(NEW)

    @staticmethod
    def _json(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def _repair(self, **kwargs):
        with patch("fuzz_target_scout.harness_repair._check_labeled_containers"):
            return repair_native_harness(
                self.config, self.job_id, self.replacement,
                "Reviewed parser harness after normal C++ exception", **kwargs,
            )

    def test_archive_rebuild_and_carry_corpus_without_crashes(self):
        result = self._repair()
        archive = self.job / result["archive"]
        state = json.loads((self.job / "state.json").read_text())
        generic = json.loads((self.artifacts / "generic-integration.json").read_text())
        manifest = json.loads((self.artifacts / "integration-manifest.json").read_text())
        self.assertEqual(result["old_crash_classification"], "uncaught_cpp_exception")
        self.assertEqual(result["carried_corpus_files"], 1)
        self.assertEqual(state["stage"], "build")
        self.assertEqual(state["status"], "integrated")
        self.assertEqual(state["attempts"], {"operator_harness_repair": 1})
        self.assertNotIn("active_fuzz_container", state)
        self.assertEqual(
            (self.job / "integration" / "native" / "generic_harness.cc").read_text(), NEW,
        )
        self.assertEqual(
            (archive / "integration" / "native" / "generic_harness.cc").read_text(), OLD,
        )
        self.assertEqual(
            (archive / "corpus" / "generic_fuzzer" / "seed").read_bytes(), b"abc",
        )
        self.assertEqual(
            (self.job / "corpus" / "generic_fuzzer" / "seed").read_bytes(), b"abc",
        )
        self.assertFalse((self.job / "crashes" / "generic_fuzzer" / "crash").exists())
        self.assertTrue((archive / "crashes" / "generic_fuzzer" / "crash").exists())
        self.assertTrue((archive / "artifacts" / "probe-run.json").exists())
        self.assertFalse((self.artifacts / "probe-run.json").exists())
        self.assertTrue((self.artifacts / "authorization-recheck.json").exists())
        self.assertTrue((self.job / "build-source" / "api.h").exists())
        digest = hashlib.sha256(NEW.encode()).hexdigest()
        self.assertEqual(generic["harness_sha256"], digest)
        self.assertEqual(manifest["integration_file_sha256"]["generic_harness.cc"], digest)
        self.assertNotIn("runner_image", manifest)

    def test_dry_run_and_seed_file(self):
        seed = self.root / "input"
        seed.write_bytes(b"more input")
        result = self._repair(dry_run=True, seed_files=(seed,))
        self.assertTrue(result["dry_run"])
        self.assertFalse((self.artifacts / "history").exists())
        self.assertEqual((self.job / "integration" / "native" / "generic_harness.cc").read_text(), OLD)
        self._repair(seed_files=(seed,))
        digest = hashlib.sha256(seed.read_bytes()).hexdigest()
        self.assertEqual(
            (self.job / "corpus" / "generic_fuzzer" / digest).read_bytes(),
            b"more input",
        )

    def test_skipped_after_recovery_is_allowed(self):
        state = json.loads((self.job / "state.json").read_text())
        state.update({"status": "skipped_after_recovery", "stage": "complete"})
        self._json(self.job / "state.json", state)
        self._repair()
        self.assertEqual(
            json.loads((self.job / "state.json").read_text())["stage"], "build",
        )

    def test_stale_manifest_harness_hash_is_archived_and_repaired(self):
        manifest_path = self.artifacts / "integration-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["integration_file_sha256"]["generic_harness.cc"] = "older-repair-hash"
        self._json(manifest_path, manifest)
        result = self._repair()
        self.assertTrue(result["old_manifest_harness_hash_stale"])
        self.assertEqual(result["old_manifest_harness_sha256"], "older-repair-hash")
        archive = self.job / result["archive"]
        archived = json.loads(
            (archive / "artifacts" / "integration-manifest.json").read_text()
        )
        self.assertEqual(
            archived["integration_file_sha256"]["generic_harness.cc"],
            "older-repair-hash",
        )
        current = json.loads(manifest_path.read_text())
        self.assertEqual(
            current["integration_file_sha256"]["generic_harness.cc"],
            hashlib.sha256(NEW.encode()).hexdigest(),
        )

    def test_old_review_without_diagnostics_uses_probe_log(self):
        self._json(self.artifacts / "quartet-review.json", {"facts": {}})
        result = self._repair(dry_run=True)
        self.assertEqual(result["old_crash_classification"], "uncaught_cpp_exception")

    def test_corpus_over_limit_stays_only_in_archive(self):
        (self.job / "corpus" / "generic_fuzzer" / "large").write_bytes(b"abcd")
        with patch.object(repair_module, "MAX_CARRY_FILE_BYTES", 3):
            result = self._repair()
        archive = self.job / result["archive"]
        self.assertEqual(result["carried_corpus_files"], 1)
        self.assertEqual(result["archive_only_corpus_files"], 1)
        self.assertTrue(
            (archive / "corpus" / "generic_fuzzer" / "large").is_file()
        )
        self.assertFalse(
            (self.job / "corpus" / "generic_fuzzer" / "large").exists()
        )

    def test_refuses_bad_candidate_dirty_source_and_hash_drift(self):
        generic_path = self.artifacts / "generic-integration.json"
        generic = json.loads(generic_path.read_text())
        generic["candidate"]["signature"] = "LLVMFuzzerTestOneInput(const uint8_t*, size_t)"
        self._json(generic_path, generic)
        with self.assertRaisesRegex(PipelineError, "API candidate"):
            self._repair()
        generic["candidate"]["signature"] = "int parse_data(const uint8_t*, size_t)"
        self._json(generic_path, generic)
        (self.job / "build-source" / "api.h").write_text("dirty")
        with self.assertRaisesRegex(PipelineError, "uncommitted changes"):
            self._repair()
        (self.job / "build-source" / "api.h").write_text(
            "#include <cstdint>\n#include <cstddef>\n"
            "int parse_data(const uint8_t*, size_t);\n"
        )
        generic["harness_sha256"] = "wrong"
        self._json(generic_path, generic)
        with self.assertRaisesRegex(PipelineError, "differs"):
            self._repair()

    def test_refuses_running_service_and_sanitizer_finding(self):
        lock_path = self.runs / ".pipeline-worker.lock"
        with lock_path.open("w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(PipelineError, "worker is active"):
                self._repair()
        with patch(
            "fuzz_target_scout.harness_repair._check_labeled_containers",
            side_effect=PipelineError("labeled Docker container"),
        ):
            with self.assertRaisesRegex(PipelineError, "labeled Docker container"):
                repair_native_harness(
                    self.config, self.job_id, self.replacement, "Reviewed", dry_run=True,
                )
        (self.job / "logs" / "probe-generic_fuzzer.log").write_text(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PipelineError, "finding review"):
            self._repair()

    def test_untriaged_crash_refuses_repair(self):
        (self.job / "logs" / "probe-generic_fuzzer.log").write_text(
            "nothing diagnostic\n", encoding="utf-8",
        )
        with self.assertRaisesRegex(PipelineError, "untriaged crash"):
            self._repair()

    def test_docker_check_includes_stopped_containers_and_fails_closed(self):
        with patch("fuzz_target_scout.harness_repair.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "old-stopped-container\n"
            with self.assertRaisesRegex(PipelineError, "labeled Docker container"):
                repair_module._check_labeled_containers()
            self.assertIn("--all", run.call_args.args[0])
            run.return_value.returncode = 1
            run.return_value.stderr = "daemon unavailable"
            with self.assertRaisesRegex(PipelineError, "cannot verify Docker"):
                repair_module._check_labeled_containers()

    def test_refuses_reproduced_finding_evidence(self):
        self._json(self.artifacts / "triage-history" / "old.json", {
            "validated_group_count": 1,
        })
        with self.assertRaisesRegex(PipelineError, "reproduced finding"):
            self._repair()

    def test_failed_state_write_restores_active_evidence(self):
        original = repair_module._write_json

        def fail_state(path, value):
            if path == self.job / "state.json":
                raise OSError("simulated state failure")
            return original(path, value)

        with patch("fuzz_target_scout.harness_repair._write_json", side_effect=fail_state):
            with self.assertRaisesRegex(OSError, "simulated state failure"):
                self._repair()
        self.assertEqual(
            (self.job / "integration" / "native" / "generic_harness.cc").read_text(), OLD,
        )
        self.assertTrue((self.artifacts / "probe-run.json").exists())
        self.assertTrue((self.job / "crashes" / "generic_fuzzer" / "crash").exists())
        self.assertEqual(
            json.loads((self.job / "state.json").read_text())["status"],
            "quartet_review_required",
        )


if __name__ == "__main__":
    unittest.main()
