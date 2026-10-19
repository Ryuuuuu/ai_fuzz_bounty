import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.operations import Housekeeper, directory_size, pipeline_overview
from fuzz_target_scout.pipeline import PipelineInterrupted


class OperationsTests(unittest.TestCase):
    def test_native_merge_keeps_old_coverage_seed_and_preserves_evidence(self):
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
            self._native_manifest(job)

            def merge(command, **_kwargs):
                if command[:2] == ["docker", "run"]:
                    self.assertIn("-merge=1", command)
                    self.assertNotIn("--label", command)
                    self.assertEqual(command[command.index("--pull") + 1], "never")
                    output_mount = next(value for value in command if value.endswith(":/merge-output:rw"))
                    output = Path(output_mount.split(":", 1)[0])
                    (output / "keep-old").write_bytes((corpus / "0").read_bytes())
                    (output / "keep-new").write_bytes((corpus / "2").read_bytes())
                return subprocess.CompletedProcess(command, 0)

            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.subprocess.run", side_effect=merge):
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            self.assertTrue((corpus / "0").exists())
            self.assertFalse((corpus / "1").exists())
            self.assertTrue((corpus / "2").exists())
            self.assertTrue(evidence.is_file())
            self.assertEqual(result["jobs"][0]["removed_files"], 1)
            self.assertEqual(result["jobs"][0]["corpus_compactions"][0]["status"], "merged")

    def test_failed_merge_keeps_all_inputs_and_sets_resource_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / str(index)).write_bytes(bytes([index]))
            self._native_manifest(job)

            def failed_merge(command, **_kwargs):
                return subprocess.CompletedProcess(command, 1 if command[:2] == ["docker", "run"] else 0)

            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.subprocess.run", side_effect=failed_merge):
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            self.assertEqual(len(list(corpus.iterdir())), 3)
            self.assertEqual(result["jobs"][0]["corpus_compactions"][0]["status"], "merge_execution_failed")
            self.assertEqual(json.loads((job / "state.json").read_text())["status"], "resource_limit_required")

    def test_merge_temp_creation_failure_keeps_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / str(index)).write_bytes(bytes([index]))
            self._native_manifest(job)
            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.tempfile.TemporaryDirectory", side_effect=OSError("disk")), \
                 patch("fuzz_target_scout.operations.subprocess.run") as docker:
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            docker.assert_not_called()
            self.assertEqual(len(list(corpus.iterdir())), 3)
            self.assertEqual(result["jobs"][0]["corpus_compactions"][0]["status"], "merge_temporary_directory_failed")

    def test_merge_temp_cleanup_failure_returns_resource_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / str(index)).write_bytes(bytes([index]))
            self._native_manifest(job)
            real_temporary_directory = tempfile.TemporaryDirectory

            def failing_cleanup(*args, **kwargs):
                actual = real_temporary_directory(*args, **kwargs)

                class Temporary:
                    name = actual.name

                    def cleanup(self):
                        actual.cleanup()
                        raise OSError("cleanup")

                return Temporary()

            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.tempfile.TemporaryDirectory", side_effect=failing_cleanup), \
                 patch("fuzz_target_scout.operations.subprocess.run", side_effect=lambda command, **kwargs: subprocess.CompletedProcess(command, 1)):
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            self.assertEqual(len(list(corpus.iterdir())), 3)
            compact = result["jobs"][0]["corpus_compactions"][0]
            self.assertEqual(compact["status"], "merge_execution_failed")
            self.assertTrue(compact["cleanup_failed"])
            self.assertTrue(result["jobs"][0]["over_limit"])

    def test_merge_and_verification_share_one_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / str(index)).write_bytes(bytes([index]))
            self._native_manifest(job)
            observed_timeouts = []

            def slow_merge(command, **kwargs):
                if command[:2] == ["docker", "run"]:
                    observed_timeouts.append(kwargs["timeout"])
                    time.sleep(0.02)
                    output_mount = next(value for value in command if value.endswith(":/merge-output:rw"))
                    output = Path(output_mount.split(":", 1)[0])
                    (output / "keep-0").write_bytes((corpus / "0").read_bytes())
                    (output / "keep-2").write_bytes((corpus / "2").read_bytes())
                return subprocess.CompletedProcess(command, 0)

            with patch("fuzz_target_scout.operations.MERGE_TIMEOUT_SECONDS", 0.01), \
                 patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.subprocess.run", side_effect=slow_merge):
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            self.assertEqual(len(list(corpus.iterdir())), 3)
            self.assertEqual(result["jobs"][0]["corpus_compactions"][0]["status"], "merge_verification_timeout")
            self.assertEqual(len(observed_timeouts), 1)
            self.assertLessEqual(observed_timeouts[0], 0.01)

    def test_invalid_merge_output_keeps_every_original_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / str(index)).write_bytes(bytes([index]))
            self._native_manifest(job)

            def invalid_merge(command, **_kwargs):
                if command[:2] == ["docker", "run"]:
                    output_mount = next(value for value in command if value.endswith(":/merge-output:rw"))
                    output = Path(output_mount.split(":", 1)[0])
                    (output / "not-an-original-input").write_bytes(b"x")
                return subprocess.CompletedProcess(command, 0)

            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.subprocess.run", side_effect=invalid_merge):
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            self.assertEqual(len(list(corpus.iterdir())), 3)
            self.assertEqual(result["jobs"][0]["corpus_compactions"][0]["status"], "merge_output_invalid")

    def test_active_fuzz_defers_merge_without_deleting_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / str(index)).write_bytes(bytes([index]))
            state_path = job / "state.json"
            state = json.loads(state_path.read_text())
            state.update(status="running", active_fuzz_container="fts-active")
            state_path.write_text(json.dumps(state))
            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.subprocess.run") as docker:
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            docker.assert_not_called()
            self.assertEqual(len(list(corpus.iterdir())), 3)
            self.assertEqual(result["jobs"][0]["corpus_compactions"][0]["status"], "active_fuzz_deferred")
            self.assertEqual(json.loads(state_path.read_text())["status"], "running")

    def test_nested_corpus_below_limit_is_left_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            nested = corpus / "fixtures"
            nested.mkdir(parents=True)
            (nested / "seed").write_bytes(b"seed")
            (corpus / "flat").write_bytes(b"flat")
            (corpus / "alias").symlink_to(nested / "seed")
            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.subprocess.run") as docker:
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            docker.assert_not_called()
            self.assertTrue((nested / "seed").is_file())
            self.assertTrue((corpus / "flat").is_file())
            self.assertTrue((corpus / "alias").is_symlink())
            self.assertFalse(result["jobs"][0]["over_limit"])
            self.assertEqual(result["jobs"][0]["corpus_compactions"], [])

    def test_nested_corpus_above_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            nested = corpus / "fixtures"
            nested.mkdir(parents=True)
            (nested / "seed").write_bytes(b"seed")
            (corpus / "flat").write_bytes(b"flat")
            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.subprocess.run") as docker:
                result = Housekeeper(self._config(root, corpus_max_files=1)).run(job.name)
            docker.assert_not_called()
            self.assertTrue((nested / "seed").is_file())
            self.assertTrue((corpus / "flat").is_file())
            self.assertTrue(result["jobs"][0]["over_limit"])
            self.assertEqual(result["jobs"][0]["corpus_compactions"][0]["status"], "unsafe_corpus")

    def test_merge_input_cap_does_not_override_higher_configured_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / str(index)).write_bytes(bytes([index]))
            with patch("fuzz_target_scout.operations.MERGE_MAX_INPUT_FILES", 2), \
                 patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]):
                result = Housekeeper(self._config(root, corpus_max_files=3)).run(job.name)
            self.assertEqual(len(list(corpus.iterdir())), 3)
            self.assertEqual(result["jobs"][0]["corpus_compactions"], [])
            self.assertFalse(result["jobs"][0]["over_limit"])

    def test_manifest_with_external_output_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / str(index)).write_bytes(bytes([index]))
            self._native_manifest(job)
            manifest_path = job / "artifacts" / "build-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            external = root / "outside-job"
            external.mkdir()
            (external / "fuzz").write_bytes(b"binary")
            manifest["output_directory"] = str(external)
            manifest_path.write_text(json.dumps(manifest))
            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.subprocess.run") as docker:
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            docker.assert_not_called()
            self.assertEqual(len(list(corpus.iterdir())), 3)
            self.assertEqual(result["jobs"][0]["corpus_compactions"][0]["status"], "merge_unavailable")

    def test_malformed_manifest_targets_are_rejected_without_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / str(index)).write_bytes(bytes([index]))
            self._native_manifest(job)
            manifest_path = job / "artifacts" / "build-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["fuzz_targets"] = None
            manifest_path.write_text(json.dumps(manifest))
            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]), \
                 patch("fuzz_target_scout.operations.subprocess.run") as docker:
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            docker.assert_not_called()
            self.assertEqual(len(list(corpus.iterdir())), 3)
            self.assertEqual(result["jobs"][0]["corpus_compactions"][0]["status"], "merge_unavailable")

    def test_missing_native_build_does_not_delete_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            corpus = job / "corpus" / "fuzz"
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / str(index)).write_bytes(bytes([index]))
            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]):
                result = Housekeeper(self._config(root, corpus_max_files=2)).run(job.name)
            self.assertEqual(len(list(corpus.iterdir())), 3)
            self.assertEqual(result["jobs"][0]["corpus_compactions"][0]["status"], "merge_unavailable")

    @staticmethod
    def _native_manifest(job: Path) -> None:
        out_dir = job / "native-out"
        out_dir.mkdir()
        (out_dir / "fuzz").write_bytes(b"binary")
        (job / "artifacts" / "build-manifest.json").write_text(json.dumps({
            "execution_mode": "native_container",
            "fuzz_targets": ["fuzz"],
            "runner_image": "native-test-image",
            "output_directory": str(out_dir),
        }))

    def test_completed_job_removes_transient_workspaces_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            state_path = job / "state.json"
            state = json.loads(state_path.read_text())
            state.update({"stage": "complete", "status": "exhausted"})
            state_path.write_text(json.dumps(state))
            old = time.time() - 7200
            os.utime(state_path, (old, old))
            for name in ("native-work", "native-out", "build-output", "source"):
                path = job / name
                path.mkdir()
                (path / "temporary").write_bytes(b"x" * 10)
            evidence = job / "artifacts" / "triage-summary.json"
            evidence.write_text(json.dumps({"validated_group_count": 0}))
            with patch.object(Housekeeper, "_clean_orphan_containers", return_value=[]):
                result = Housekeeper(
                    self._config(root, runtime_retention_hours=1)
                ).run(job.name)
            self.assertTrue(evidence.is_file())
            self.assertFalse((job / "native-work").exists())
            self.assertFalse((job / "source").exists())
            self.assertIn("native-work", result["jobs"][0]["removed_workspaces"])

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
            self.assertTrue(value["disk_usage_complete"])

    def test_fast_overview_does_not_walk_job_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            with patch(
                "fuzz_target_scout.operations.directory_size",
                side_effect=AssertionError("unexpected disk walk"),
            ):
                value = pipeline_overview(root, include_disk_usage=False)
            self.assertEqual(value["jobs"][0]["job_id"], job.name)
            self.assertIsNone(value["jobs"][0]["disk_bytes"])
            self.assertIsNone(value["total_disk_bytes"])
            self.assertFalse(value["disk_usage_complete"])

    def test_targeted_cleanup_can_defer_orphan_scan_to_full_sweep(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            keeper = Housekeeper(self._config(root))
            with patch.object(keeper, "_clean_orphan_containers") as docker_cleanup:
                result = keeper.run(job.name, clean_orphan_containers=False)
                self.assertEqual(result["jobs"][0]["job_id"], job.name)
                docker_cleanup.assert_not_called()
                keeper.run()
                docker_cleanup.assert_called_once()

    def test_periodic_cleanup_only_visits_completed_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = self._job(root)
            completed = root / "org-completed-bbbbbbbbbbbb"
            completed.mkdir()
            (completed / "state.json").write_text(json.dumps({
                "job_id": completed.name, "stage": "complete", "status": "exhausted",
            }))
            (active / "logs" / "keep.log").write_text("active")
            (completed / "logs").mkdir()
            (completed / "logs" / "old.log").write_text("completed")
            keeper = Housekeeper(self._config(root, log_max_files=0))
            with patch.object(keeper, "_clean_orphan_containers") as docker_cleanup:
                result = keeper.run(
                    clean_orphan_containers=False, completed_only=True
                )
            self.assertFalse(result["skipped_busy"])
            self.assertEqual([item["job_id"] for item in result["jobs"]], [
                completed.name,
            ])
            self.assertTrue((active / "logs" / "keep.log").is_file())
            self.assertFalse((completed / "logs" / "old.log").exists())
            docker_cleanup.assert_not_called()

    def test_housekeeping_lock_skips_overlapping_sweep(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            entered = threading.Event()
            release = threading.Event()
            first = Housekeeper(self._config(root))
            second = Housekeeper(self._config(root))
            result = []

            def slow_clean(path):
                entered.set()
                release.wait(5)
                return {"job_id": path.name}

            with patch.object(first, "_clean_job", side_effect=slow_clean), patch.object(
                first, "_clean_orphan_containers", return_value=[]
            ), patch.object(second, "_clean_job") as duplicate:
                thread = threading.Thread(
                    target=lambda: result.append(first.run(job.name))
                )
                thread.start()
                try:
                    self.assertTrue(entered.wait(2))
                    busy = second.run(job.name)
                    self.assertTrue(busy["skipped_busy"])
                    duplicate.assert_not_called()
                finally:
                    release.set()
                    thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertFalse(result[0]["skipped_busy"])

    def test_directory_scan_stops_between_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").write_bytes(b"a")
            event = threading.Event()

            def walk(*_args, **_kwargs):
                yield str(root), [], ["a"]
                event.set()
                yield str(root), [], ["a"]

            with patch("fuzz_target_scout.operations.os.walk", side_effect=walk):
                with self.assertRaises(PipelineInterrupted):
                    directory_size(root, cancel_event=event)

    def test_housekeeper_does_not_continue_after_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = self._job(root)
            event = threading.Event()
            keeper = Housekeeper(self._config(root), cancel_event=event)

            def stop_during_cleanup(_job_dir):
                event.set()
                return {"job_id": job.name}

            with patch.object(keeper, "_clean_job", side_effect=stop_during_cleanup), patch.object(
                keeper, "_clean_orphan_containers"
            ) as docker_cleanup:
                with self.assertRaises(PipelineInterrupted):
                    keeper.run()
                docker_cleanup.assert_not_called()

    def test_running_merge_is_cancelled_without_waiting_for_full_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event = threading.Event()
            keeper = Housekeeper(self._config(root), cancel_event=event)
            timer = threading.Timer(0.2, event.set)
            timer.start()
            started = time.monotonic()
            try:
                with self.assertRaises(PipelineInterrupted):
                    keeper._run_merge(
                        [sys.executable, "-c", "import time; time.sleep(30)"],
                        time.monotonic() + 30,
                    )
            finally:
                timer.cancel()
            self.assertLess(time.monotonic() - started, 5)

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
