from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.arm_preflight import (
    ArmPreflight,
    ArmPreflightResult,
    BUILD_AND_SMOKE,
    PREFLIGHT_VERSION,
    SELECT_NATIVE_TEST,
    VERIFY_NATIVE_TEST,
    _StepFailure,
    _failure_evidence,
)
from fuzz_target_scout.config import load_config
from fuzz_target_scout.engine import ScoutEngine
from fuzz_target_scout.models import (
    ArchitectureAssessment,
    Candidate,
    PolicyAssessment,
    RepoSnapshot,
    StaticAssessment,
)
from fuzz_target_scout.pipeline import load_toolchain_lock, make_work_order


SHA = "a" * 40


def repository(name: str = "org/parser") -> RepoSnapshot:
    return RepoSnapshot(
        full_name=name,
        html_url=f"https://github.com/{name}",
        default_branch="main",
        head_sha=SHA,
        language="C++",
        size_kb=100,
        security_url=f"https://github.com/{name}/security/policy",
    )


def candidate(
    name: str = "org/parser", *, status: str = "verified",
    blockers: list[str] | None = None, build: bool = True,
) -> Candidate:
    return Candidate(
        repo=repository(name),
        static=StaticAssessment(
            fuzz_score=80,
            reproduce_difficulty=1,
            signals=["standard_build:cmakelists.txt"] if build else [],
            blockers=["no_explicit_native_support_evidence:aarch64"],
            suggested_entry_kind="library_api",
        ),
        policy=PolicyAssessment(
            status=status,
            confidence=85,
            source="security.md",
            program_url="https://hackerone.com/org",
            note="Explicit paid scope",
        ),
        final_score=80,
        architecture=ArchitectureAssessment(
            host_arch="aarch64",
            compatible=False,
            confidence=100,
            blockers=blockers or ["no_explicit_native_support_evidence:aarch64"],
        ),
    )


class ArmPreflightTests(unittest.TestCase):
    def test_success_requires_pinned_checkout_native_build_and_test_smoke(self):
        checker = ArmPreflight({"host_arch": "aarch64"})
        commands = []
        environments = []

        def fake_run(command, _deadline, environment, _failure):
            commands.append(command)
            environments.append(environment)
            if command[0] == "git" and "checkout" in command:
                (Path(command[2]) / "CMakeLists.txt").write_text(
                    "project(parser)", encoding="utf-8"
                )
            if command[0] == "git" and "rev-parse" in command:
                return subprocess.CompletedProcess(command, 0, SHA + "\n", "")
            if command[:2] == ["docker", "run"]:
                return subprocess.CompletedProcess(
                    command, 0, "FTS_ARM_PREFLIGHT_OK\n", ""
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("fuzz_target_scout.arm_preflight.platform.machine", return_value="aarch64"), patch.object(
            checker, "_run", side_effect=fake_run
        ), patch.object(checker, "_ensure_builder"), patch(
            "fuzz_target_scout.arm_preflight.subprocess.run"
        ) as cleanup, patch.dict(os.environ, {"GITHUB_TOKEN": "should-not-leak"}):
            result = checker.check(repository())

        self.assertTrue(result.passed)
        self.assertIn(SHA, result.evidence)
        self.assertEqual(cleanup.call_count, 1)
        container = next(command for command in commands if command[:2] == ["docker", "run"])
        self.assertIn("none", container)
        self.assertIn("--read-only", container)
        self.assertIn("--cap-drop", container)
        self.assertIn("no-new-privileges:true", container)
        self.assertIn("--memory", container)
        self.assertIn("--cpus", container)
        self.assertIn("65534:65534", container)
        self.assertTrue(
            container[container.index("--mount") + 1].endswith(
                ",target=/src,readonly"
            )
        )
        self.assertIn("ctest --test-dir /work/build", container[-1])
        self.assertTrue(all("GITHUB_TOKEN" not in env for env in environments))

    def test_google_test_source_path_is_conditional_and_shell_valid(self):
        self.assertIn(
            "[ -f /usr/src/googletest/googlemock/CMakeLists.txt ]",
            BUILD_AND_SMOKE,
        )
        self.assertIn("set -- -DGOOGLETEST_PATH=/usr/src/googletest", BUILD_AND_SMOKE)
        self.assertIn("set --\nfi\ncmake -S /src", BUILD_AND_SMOKE)
        self.assertIn('-DFETCHCONTENT_FULLY_DISCONNECTED=ON "$@"', BUILD_AND_SMOKE)
        self.assertIn("verify_native_test.py", BUILD_AND_SMOKE)
        self.assertIn("--candidates /work/build /src > /work/candidates.txt", BUILD_AND_SMOKE)
        self.assertIn(
            'if cmake --build /work/build --target "$candidate" --parallel 2; then',
            BUILD_AND_SMOKE,
        )
        self.assertIn('if [ "$built_any" -eq 0 ]; then', BUILD_AND_SMOKE)
        result = subprocess.run(
            ["/bin/sh", "-n"], input=BUILD_AND_SMOKE,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_reports_failed_stage_on_command_error(self):
        probe_script = (
            "stage=configure\n"
            + BUILD_AND_SMOKE.split("stage=configure\n", 1)[1].split("cmake -S ", 1)[0]
            + "false\n"
        )
        result = subprocess.run(
            ["/bin/sh", "-ec", probe_script], capture_output=True, text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FTS_ARM_PREFLIGHT_FAILED_STAGE:configure:1", result.stderr)
        self.assertIn(
            "stage=configure",
            _failure_evidence(result.stdout + result.stderr, result.returncode),
        )

    def test_build_without_smoke_marker_does_not_claim_arm_support(self):
        checker = ArmPreflight({"host_arch": "aarch64"})

        def fake_run(command, _deadline, _environment, _failure):
            if command[0] == "git" and "checkout" in command:
                (Path(command[2]) / "CMakeLists.txt").write_text("project(parser)")
            stdout = SHA if command[0] == "git" and "rev-parse" in command else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")

        with patch("fuzz_target_scout.arm_preflight.platform.machine", return_value="aarch64"), patch.object(
            checker, "_run", side_effect=fake_run
        ), patch.object(checker, "_ensure_builder"), patch(
            "fuzz_target_scout.arm_preflight.subprocess.run"
        ):
            result = checker.check(repository())
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "smoke_marker_missing")

    def test_selector_requires_real_compiled_ctest_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            build = root / "build"
            reply = build / ".cmake/api/v1/reply"
            source.mkdir()
            reply.mkdir(parents=True)
            cpp = source / "unit.cpp"
            cpp.write_text("int main() { return 0; }\n")
            (build / "compile_commands.json").write_text(json.dumps([{
                "directory": str(build),
                "file": str(cpp),
                "command": f"clang++ -c {cpp}",
            }]))
            (reply / "index-fixture.json").write_text(json.dumps({
                "reply": {"codemodel-v2": {"jsonFile": "model.json"}}
            }))
            (reply / "model.json").write_text(json.dumps({
                "configurations": [{"targets": [{
                    "name": "unit", "jsonFile": "target.json",
                }]}]
            }))
            (reply / "target.json").write_text(json.dumps({
                "type": "EXECUTABLE",
                "compileGroups": [{"language": "CXX"}],
                "sources": [{"path": str(cpp), "compileGroupIndex": 0}],
                "artifacts": [{"path": "unit"}],
            }))
            tests_path = root / "tests.json"
            tests_path.write_text(json.dumps({"tests": [
                {"name": "script", "command": ["/usr/bin/cmake", "-E", "echo", "ok"]},
                {"name": "unit", "command": [str(build / "unit")]},
            ]}))
            scope = {"__name__": "selector_fixture"}
            exec(SELECT_NATIVE_TEST, scope)
            chosen = scope["select_native_test"](build, source, tests_path)
            self.assertEqual(chosen["target"], "unit")
            self.assertEqual(chosen["test_index"], 2)
            self.assertEqual(chosen["artifact"], str(build / "unit"))

            tests_path.write_text(json.dumps({"tests": [
                {"name": "script", "command": ["/usr/bin/cmake", "-E", "echo", "ok"]},
            ]}))
            with self.assertRaisesRegex(ValueError, "no CTest executable"):
                scope["select_native_test"](build, source, tests_path)
            self.assertEqual(
                scope["select_native_test"](build, source, tests_path, candidates=True),
                ["unit"],
            )
            # CTest can omit the command of an unbuilt executable. Building
            # the File API candidate makes its command discoverable.
            tests_path.write_text(json.dumps({"tests": [{"name": "unit"}]}))
            with self.assertRaisesRegex(ValueError, "no CTest executable"):
                scope["select_native_test"](build, source, tests_path)
            tests_path.write_text(json.dumps({"tests": [
                {"name": "unit", "command": [str(build / "unit")]},
            ]}))
            self.assertEqual(
                scope["select_native_test"](build, source, tests_path)["target"],
                "unit",
            )
            (reply / "target.json").write_text(json.dumps({
                "type": "EXECUTABLE",
                "compileGroups": [],
                "sources": [{"path": str(cpp)}],
                "artifacts": [{"path": "unit"}],
            }))
            with self.assertRaisesRegex(ValueError, "no CTest executable"):
                scope["select_native_test"](build, source, tests_path)

    def test_candidate_target_selection_is_bounded_and_safe(self):
        scope = {"__name__": "selector_fixture"}
        exec(SELECT_NATIVE_TEST, scope)
        names = [
            "smoke_a", "test_b", "benchmark", "test_a", "unit_a",
            "test;bad", "test_a", "spec_a",
        ]
        targets = [(Path("/work/build") / name, name) for name in names]
        self.assertEqual(
            scope["candidate_targets"](targets),
            ["test_a", "test_b", "unit_a"],
        )

    def test_smoke_requires_aarch64_elf_and_runs_selected_test(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            artifact = build / "unit"
            header = bytearray(20)
            header[:4] = b"\x7fELF"
            header[5] = 1
            header[18:20] = (183).to_bytes(2, "little")
            artifact.write_bytes(header)
            artifact.chmod(0o755)
            selection = build / "selection.json"
            selection.write_text(json.dumps({
                "artifact": str(artifact), "test_index": 2,
            }))
            scope = {"__name__": "smoke_fixture"}
            exec(VERIFY_NATIVE_TEST, scope)
            result = subprocess.CompletedProcess(
                [], 0, "100% tests passed, 0 tests failed out of 1\n", ""
            )
            with patch("subprocess.run", return_value=result) as run:
                scope["verify_native_test"](build, selection)
            self.assertIn("2,2", run.call_args.args[0])

            header[18:20] = (62).to_bytes(2, "little")
            artifact.write_bytes(header)
            with patch("subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "not AArch64"):
                    scope["verify_native_test"](build, selection)
                run.assert_not_called()

    def test_process_deadline_is_not_reported_as_build_failure(self):
        checker = ArmPreflight({"host_arch": "aarch64"})
        with self.assertRaisesRegex(_StepFailure, "preflight_timeout"):
            checker._try_run(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                time.monotonic() - 1,
                {},
            )

    def test_docker_run_startup_error_is_not_a_source_build_failure(self):
        checker = ArmPreflight({"host_arch": "aarch64"})
        command = ["docker", "run", "image"]
        with patch.object(
            checker, "_try_run",
            return_value=subprocess.CompletedProcess(command, 125, "", ""),
        ):
            with self.assertRaisesRegex(_StepFailure, "builder_unavailable") as raised:
                checker._run(
                    command, time.monotonic() + 10, {}, "native_build_or_smoke_failed"
                )
        self.assertIn("stage=container_start", raised.exception.evidence)

    def test_failed_build_keeps_actionable_evidence_without_raw_output(self):
        checker = ArmPreflight({"host_arch": "aarch64"})
        secret = "ghp_" + "S" * 36

        def fake_try_run(command, _deadline, _environment, *, preserve_failure=False):
            if command[0] == "git" and "checkout" in command:
                (Path(command[2]) / "CMakeLists.txt").write_text("project(parser)")
            if command[0] == "git" and "rev-parse" in command:
                return subprocess.CompletedProcess(command, 0, SHA + "\n", "")
            if command[:2] == ["docker", "run"]:
                output = (
                    "FTS_ARM_PREFLIGHT_STAGE:build\n"
                    + "clang: fatal error: missing.hpp: No such file or directory\n"
                    + f"password={secret}\n" * 100
                    + "FTS_ARM_PREFLIGHT_FAILED_STAGE:build:1\n"
                )
                return subprocess.CompletedProcess(command, 1, output, "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("fuzz_target_scout.arm_preflight.platform.machine", return_value="aarch64"), patch.object(
            checker, "_try_run", side_effect=fake_try_run
        ), patch.object(checker, "_ensure_builder"), patch(
            "fuzz_target_scout.arm_preflight.subprocess.run"
        ):
            result = checker.check(repository())
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "native_build_or_smoke_failed")
        self.assertIn("stage=build", result.evidence)
        self.assertIn("kind=missing_header", result.evidence)
        self.assertNotIn(secret, result.evidence)
        self.assertNotIn("missing.hpp", result.evidence)
        self.assertLess(len(result.evidence), 160)

        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            engine = ScoutEngine(config)
            try:
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = result
                    self.assertEqual(engine._preflight_arm_candidates([candidate()]), (1, 0))
                cached = engine.store.get_arm_preflight(
                    "org/parser", SHA, "aarch64", PREFLIGHT_VERSION
                )
                self.assertEqual(cached["evidence"], result.evidence)
                self.assertNotIn(secret, cached["evidence"])
            finally:
                engine.close()

    def test_ctest_failure_evidence_keeps_counts_without_test_output(self):
        secret = "test output contains a password"
        output = (
            "FTS_ARM_PREFLIGHT_STAGE:smoke\n"
            + secret + "\n"
            + "0% tests passed, 1 tests failed out of 1\n"
            + "FTS_ARM_PREFLIGHT_FAILED_STAGE:smoke:1\n"
        )
        evidence = _failure_evidence(output, 1)
        self.assertIn("stage=smoke", evidence)
        self.assertIn("kind=ctest_failed", evidence)
        self.assertIn("failed_tests=1/1", evidence)
        self.assertNotIn(secret, evidence)
        self.assertLess(len(evidence), 160)

    def test_native_selection_failure_has_specific_safe_category(self):
        output = (
            "FTS_ARM_PREFLIGHT_STAGE:select_native_test\n"
            "native test selection failed: no CTest executable backed by a C/C++ CMake target\n"
            "FTS_ARM_PREFLIGHT_FAILED_STAGE:select_native_test:1\n"
        )
        evidence = _failure_evidence(output, 1)
        self.assertIn("kind=no_native_ctest_target", evidence)
        self.assertNotIn("native test selection failed", evidence)

    def test_non_native_host_never_starts_preflight(self):
        checker = ArmPreflight({"host_arch": "aarch64"})
        with patch("fuzz_target_scout.arm_preflight.platform.machine", return_value="x86_64"), patch.object(
            checker, "_run"
        ) as run:
            result = checker.check(repository())
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "not_native_arm_host")
        run.assert_not_called()

    def test_only_verified_paid_candidate_is_promoted_and_plannable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            config["pipeline"]["architecture"]["host_arch"] = "aarch64"
            valid = candidate()
            conditional = candidate("org/conditional", status="conditional")
            negative = candidate("org/negative", blockers=["ARM unsupported"])
            no_build = candidate("org/no-build", build=False)
            evidence = f"native_arm_preflight:{PREFLIGHT_VERSION}:cmake_build_ctest:{SHA}"
            engine = ScoutEngine(config)
            try:
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = ArmPreflightResult(
                        True, "native_arm_build_and_ctest_passed", evidence
                    )
                    attempted, passed = engine._preflight_arm_candidates(
                        [valid, conditional, negative, no_build]
                    )
                    self.assertEqual(runner.return_value.check.call_count, 1)
                self.assertEqual((attempted, passed), (1, 1))
                self.assertTrue(valid.architecture.compatible)
                self.assertFalse(conditional.architecture.compatible)
                self.assertFalse(negative.architecture.compatible)
                self.assertFalse(no_build.architecture.compatible)
                self.assertNotIn(
                    "no_explicit_native_support_evidence:aarch64",
                    valid.static.blockers,
                )

                scan_id = engine.store.start_scan("test")
                engine.store.upsert_candidate(valid, scan_id)
                exported = list(engine.store.export_rows(55, False, scan_id=scan_id))
                self.assertEqual(len(exported), 1)
                lock = load_toolchain_lock(config["pipeline"]["toolchain_lock_path"])
                work_order, reason = make_work_order(
                    exported[0], config["pipeline"], lock
                )
                self.assertIsNotNone(work_order, reason)

                repeated = candidate()
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    attempted, passed = engine._preflight_arm_candidates([repeated])
                    runner.return_value.check.assert_not_called()
                self.assertEqual((attempted, passed), (0, 1))
                self.assertTrue(repeated.architecture.compatible)
            finally:
                engine.close()

    def test_preflight_prefers_score_then_smaller_source(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            config["architecture"]["arm_preflight_max_per_scan"] = 2
            small = candidate("org/z-small")
            small.repo = replace(small.repo, size_kb=50)
            large = candidate("org/a-large")
            large.repo = replace(large.repo, size_kb=5000)
            high_score = candidate("org/b-high")
            high_score.repo = replace(high_score.repo, size_kb=10000)
            high_score.final_score = 81
            engine = ScoutEngine(config)
            try:
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = ArmPreflightResult(
                        False, "native_build_or_smoke_failed"
                    )
                    self.assertEqual(
                        engine._preflight_arm_candidates([large, small, high_score]),
                        (2, 0),
                    )
                    names = [
                        call.args[0].full_name
                        for call in runner.return_value.check.call_args_list
                    ]
                self.assertEqual(names, ["org/b-high", "org/z-small"])
            finally:
                engine.close()

    def test_previous_sha_success_only_prioritizes_current_sha_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            config["architecture"]["arm_preflight_max_per_scan"] = 2
            proven = candidate("org/proven")
            proven.final_score = 60
            fresh = candidate("org/fresh")
            fresh.final_score = 90
            wrong_version = candidate("org/wrong-version")
            wrong_version.final_score = 89
            wrong_arch = candidate("org/wrong-arch")
            wrong_arch.final_score = 88
            invalid_evidence = candidate("org/invalid-evidence")
            invalid_evidence.final_score = 87
            previous_sha = "b" * 40
            evidence = (
                f"native_arm_preflight:{PREFLIGHT_VERSION}:"
                f"cmake_build_ctest:{previous_sha}"
            )
            engine = ScoutEngine(config)
            try:
                for item, arch, version, proof in (
                    (proven, "aarch64", PREFLIGHT_VERSION, evidence),
                    (wrong_version, "aarch64", "old-version", evidence),
                    (wrong_arch, "x86_64", PREFLIGHT_VERSION, evidence),
                    (invalid_evidence, "aarch64", PREFLIGHT_VERSION, "unverified"),
                ):
                    engine.store.put_arm_preflight(
                        item.repo.full_name, previous_sha, arch, version,
                        passed=True, reason="native_arm_build_and_ctest_passed",
                        evidence=proof,
                    )
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = ArmPreflightResult(
                        False, "native_build_or_smoke_failed"
                    )
                    self.assertEqual(
                        engine._preflight_arm_candidates([
                            fresh, wrong_version, wrong_arch,
                            invalid_evidence, proven,
                        ]),
                        (2, 0),
                    )
                    checked = [
                        call.args[0]
                        for call in runner.return_value.check.call_args_list
                    ]
                self.assertEqual(
                    [repo.full_name for repo in checked],
                    ["org/proven", "org/fresh"],
                )
                self.assertTrue(all(repo.head_sha == SHA for repo in checked))
                self.assertFalse(proven.architecture.compatible)
                self.assertEqual(
                    engine.store.get_arm_preflight(
                        proven.repo.full_name, SHA, "aarch64", PREFLIGHT_VERSION,
                    )["passed"],
                    0,
                )
                self.assertEqual(
                    engine.store.get_arm_preflight(
                        proven.repo.full_name, previous_sha,
                        "aarch64", PREFLIGHT_VERSION,
                    )["passed"],
                    1,
                )
            finally:
                engine.close()

    def test_failed_probe_is_cached_for_same_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            engine = ScoutEngine(config)
            try:
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = ArmPreflightResult(
                        False, "native_build_or_smoke_failed"
                    )
                    self.assertEqual(
                        engine._preflight_arm_candidates([candidate()]), (1, 0)
                    )
                    self.assertEqual(
                        engine._preflight_arm_candidates([candidate()]), (0, 0)
                    )
                    self.assertEqual(runner.return_value.check.call_count, 1)
                cached = engine.store.get_arm_preflight(
                    "org/parser", SHA, "aarch64", PREFLIGHT_VERSION
                )
                self.assertEqual(cached["reason"], "native_build_or_smoke_failed")
                engine.store.connection.execute(
                    "UPDATE arm_preflight_cache SET checked_at=? WHERE full_name=?",
                    (
                        (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat(),
                        "org/parser",
                    ),
                )
                engine.store.connection.commit()
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    self.assertEqual(
                        engine._preflight_arm_candidates([candidate()]), (0, 0)
                    )
                    runner.return_value.check.assert_not_called()
            finally:
                engine.close()

    def test_transient_probe_failure_retries_after_short_cooldown(self):
        reasons = (
            "checkout_failed",
            "builder_unavailable",
            "preflight_timeout",
            "preflight_unavailable_or_timed_out",
        )
        for reason in reasons:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                config, _ = load_config(Path(directory) / "missing.toml")
                config["architecture"]["host_arch"] = "aarch64"
                engine = ScoutEngine(config)
                try:
                    evidence = (
                        f"native_arm_preflight:{PREFLIGHT_VERSION}:"
                        f"cmake_build_ctest:{SHA}"
                    )
                    with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                        runner.return_value.check.side_effect = [
                            ArmPreflightResult(False, reason),
                            ArmPreflightResult(
                                True, "native_arm_build_and_ctest_passed", evidence
                            ),
                        ]
                        self.assertEqual(
                            engine._preflight_arm_candidates([candidate()]), (1, 0)
                        )
                        self.assertEqual(
                            engine._preflight_arm_candidates([candidate()]), (0, 0)
                        )
                        engine.store.connection.execute(
                            "UPDATE arm_preflight_cache SET checked_at=? WHERE full_name=?",
                            (
                                (
                                    datetime.now(timezone.utc) - timedelta(minutes=16)
                                ).isoformat(),
                                "org/parser",
                            ),
                        )
                        engine.store.connection.commit()
                        self.assertEqual(
                            engine._preflight_arm_candidates([candidate()]), (1, 1)
                        )
                        self.assertEqual(runner.return_value.check.call_count, 2)
                finally:
                    engine.close()

    def test_portable_source_shape_still_requires_successful_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            portable = candidate(
                blockers=["native_build_probe_required:aarch64"]
            )
            engine = ScoutEngine(config)
            try:
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = ArmPreflightResult(
                        False, "native_build_or_smoke_failed"
                    )
                    self.assertEqual(
                        engine._preflight_arm_candidates([portable]), (1, 0)
                    )
                self.assertFalse(portable.architecture.compatible)
                self.assertEqual(
                    portable.architecture.blockers,
                    ["native_build_probe_required:aarch64"],
                )
            finally:
                engine.close()


if __name__ == "__main__":
    unittest.main()
