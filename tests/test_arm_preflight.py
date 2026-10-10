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
    DOCKERFILE,
    MESON_BUILD_AND_SMOKE,
    MESON_DOCKERFILE,
    MESON_PREFLIGHT_VERSION,
    PREFLIGHT_VERSION,
    SELECT_CMAKE_NONTEST_OPTIONS,
    SELECT_MESON_NATIVE_TEST,
    VERIFY_MESON_NATIVE_TEST,
    SELECT_NATIVE_TEST,
    VERIFY_NATIVE_TEST,
    _StepFailure,
    _failure_evidence,
    _working_tree_within_limit,
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

    def test_strict_service_umask_keeps_bind_source_readable(self):
        checker = ArmPreflight({"host_arch": "aarch64"})
        observed = {}

        def fake_run(command, _deadline, _environment, _failure):
            if command[0] == "git" and "checkout" in command:
                checkout = Path(command[2])
                (checkout / "CMakeLists.txt").write_text("project(parser)\n")
            if command[0] == "git" and "rev-parse" in command:
                return subprocess.CompletedProcess(command, 0, SHA + "\n", "")
            if command[:2] == ["docker", "run"]:
                source = Path(command[command.index("--mount") + 1].split(",")[1].split("=", 1)[1])
                observed["source_mode"] = source.stat().st_mode & 0o777
                observed["parent_mode"] = source.parent.stat().st_mode & 0o777
                return subprocess.CompletedProcess(command, 0, "FTS_ARM_PREFLIGHT_OK\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        previous = os.umask(0o077)
        try:
            with patch("fuzz_target_scout.arm_preflight.platform.machine", return_value="aarch64"), patch.object(
                checker, "_run", side_effect=fake_run
            ), patch.object(checker, "_ensure_builder"), patch(
                "fuzz_target_scout.arm_preflight.subprocess.run"
            ):
                result = checker.check(repository())
        finally:
            os.umask(previous)
        self.assertTrue(result.passed)
        self.assertEqual(observed, {"source_mode": 0o755, "parent_mode": 0o700})
        self.assertIn("libboost-dev", DOCKERFILE)
        self.assertIn("libcli11-dev", DOCKERFILE)

    def test_complete_tree_size_precedes_history_size_with_unknown_fallback(self):
        checker = ArmPreflight({
            "host_arch": "aarch64", "arm_preflight_max_repository_kb": 1,
        })
        with patch("fuzz_target_scout.arm_preflight.platform.machine", return_value="aarch64"), patch.object(
            checker, "_run", side_effect=_StepFailure("checkout_failed")
        ) as runner:
            accepted = checker.check(replace(
                repository(), size_kb=50000, source_tree_kb=1,
            ))
            self.assertEqual(accepted.reason, "checkout_failed")
            runner.assert_called_once()

            runner.reset_mock()
            too_large = checker.check(replace(
                repository(), size_kb=1, source_tree_kb=2,
            ))
            self.assertEqual(too_large.reason, "repository_size_out_of_bounds")
            runner.assert_not_called()

            unknown = checker.check(replace(
                repository(), size_kb=2, source_tree_kb=None,
            ))
            self.assertEqual(unknown.reason, "repository_size_out_of_bounds")
            runner.assert_not_called()

    def test_working_tree_limit_skips_git_metadata_and_symlink_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            metadata = source / ".git"
            metadata.mkdir()
            (metadata / "pack").write_bytes(b"x" * 4096)
            outside = root / "outside"
            outside.mkdir()
            (outside / "huge").write_bytes(b"x" * 4096)
            os.symlink(outside, source / "linked_directory", target_is_directory=True)
            nested = source / "nested"
            nested.mkdir()
            (nested / "unit.cpp").write_bytes(b"x" * 512)
            self.assertTrue(_working_tree_within_limit(source, 1024))
            (nested / "more.cpp").write_bytes(b"x" * 512)
            self.assertFalse(_working_tree_within_limit(source, 1024))

    def test_actual_checkout_over_limit_never_reaches_builder(self):
        checker = ArmPreflight({
            "host_arch": "aarch64", "arm_preflight_max_repository_kb": 1,
        })

        def fake_run(command, _deadline, _environment, _failure):
            if command[0] == "git" and "checkout" in command:
                source = Path(command[2])
                (source / "CMakeLists.txt").write_text("project(parser)\n")
                (source / "large.cpp").write_bytes(b"x" * 1024)
            if command[0] == "git" and "rev-parse" in command:
                return subprocess.CompletedProcess(command, 0, SHA + "\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("fuzz_target_scout.arm_preflight.platform.machine", return_value="aarch64"), patch.object(
            checker, "_run", side_effect=fake_run
        ), patch.object(checker, "_ensure_builder") as builder:
            result = checker.check(replace(repository(), size_kb=1))
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "repository_size_out_of_bounds")
        builder.assert_not_called()

    def test_child_process_files_use_readable_umask_under_strict_service_umask(self):
        checker = ArmPreflight({"host_arch": "aarch64"})
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            previous = os.umask(0o077)
            try:
                source.mkdir()
                source.chmod(0o755)
                command = [
                    "/bin/sh", "-c",
                    'mkdir "$1/child"; printf data > "$1/child/file"',
                    "sh", str(source),
                ]
                result = checker._try_run(
                    command, time.monotonic() + 10,
                    {"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                )
            finally:
                os.umask(previous)
            self.assertIsNotNone(result)
            self.assertEqual(source.stat().st_mode & 0o777, 0o755)
            self.assertEqual((source / "child").stat().st_mode & 0o777, 0o755)
            self.assertEqual((source / "child" / "file").stat().st_mode & 0o777, 0o644)
            self.assertEqual(Path(directory).stat().st_mode & 0o777, 0o700)

    def test_meson_preflight_uses_separate_builder_and_cache_version(self):
        checker = ArmPreflight({"host_arch": "aarch64"})
        commands = []

        def fake_run(command, _deadline, _environment, _failure):
            commands.append(command)
            if command[0] == "git" and "checkout" in command:
                (Path(command[2]) / "meson.build").write_text("project('parser', 'cpp')")
            if command[0] == "git" and "rev-parse" in command:
                return subprocess.CompletedProcess(command, 0, SHA + "\n", "")
            if command[:2] == ["docker", "run"]:
                return subprocess.CompletedProcess(command, 0, "FTS_ARM_PREFLIGHT_OK\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("fuzz_target_scout.arm_preflight.platform.machine", return_value="aarch64"), patch.object(
            checker, "_run", side_effect=fake_run
        ), patch.object(checker, "_ensure_builder") as builder, patch(
            "fuzz_target_scout.arm_preflight.subprocess.run"
        ):
            result = checker.check(repository())

        self.assertTrue(result.passed)
        self.assertNotEqual(PREFLIGHT_VERSION, MESON_PREFLIGHT_VERSION)
        self.assertIn(f"native_arm_preflight:{MESON_PREFLIGHT_VERSION}:meson_build_meson_test:{SHA}", result.evidence)
        self.assertIn("libgmock-dev", MESON_DOCKERFILE)
        self.assertIn("libjsoncpp-dev", MESON_DOCKERFILE)
        self.assertEqual(builder.call_args.kwargs["dockerfile"], MESON_DOCKERFILE)
        container = next(command for command in commands if command[:2] == ["docker", "run"])
        self.assertIn("--network", container)
        self.assertIn("none", container)
        self.assertIn("--read-only", container)
        self.assertIn("--cap-drop", container)
        self.assertIn("--memory", container)
        self.assertIn("--pids-limit", container)
        self.assertEqual(container[-1], MESON_BUILD_AND_SMOKE)
        self.assertIn("--wrap-mode=nodownload", container[-1])
        self.assertIn("ninja -C /work/build", container[-1])
        self.assertEqual(subprocess.run(["/bin/sh", "-n"], input=MESON_BUILD_AND_SMOKE,
                                        capture_output=True, text=True).returncode, 0)

    def test_meson_selection_requires_compiled_executable_test_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            build = root / "build"
            info = build / "meson-info"
            source.mkdir()
            info.mkdir(parents=True)
            cpp = source / "unit.cpp"
            cpp.write_text("int main() { return 0; }\n")
            executable = build / "unit_tests"
            (build / "compile_commands.json").write_text(json.dumps([{
                "directory": str(build), "file": str(cpp),
                "command": f"clang++ -c {cpp}",
            }]))
            (info / "intro-targets.json").write_text(json.dumps([{
                "type": "executable", "filename": [str(executable)],
                "target_sources": [{"language": "cpp", "sources": [str(cpp)]}],
            }]))
            (info / "intro-tests.json").write_text(json.dumps([
                {"name": "script", "cmd": ["/usr/bin/python3", "check.py"]},
                {"name": "unit", "protocol": "exitcode", "cmd": [str(executable)],
                 "workdir": str(source)},
            ]))
            scope = {"__name__": "meson_selector_fixture"}
            exec(SELECT_MESON_NATIVE_TEST, scope)
            selected = scope["select_meson_native_test"](build, source)
            self.assertEqual(selected["target"], "unit_tests")
            self.assertEqual(selected["command"], [str(executable)])
            (info / "intro-targets.json").write_text(json.dumps([{
                "type": "executable", "filename": [str(executable)],
                "target_sources": [{"language": "cpp", "sources": [str(source / 'other.cpp')]}],
            }]))
            with self.assertRaisesRegex(ValueError, "no Meson test backed"):
                scope["select_meson_native_test"](build, source)

    def test_meson_smoke_requires_aarch64_elf_and_passing_native_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            build = root / "build"
            source.mkdir()
            build.mkdir()
            artifact = build / "unit_tests"
            header = bytearray(20)
            header[:4] = b"\x7fELF"
            header[5] = 1
            header[18:20] = (183).to_bytes(2, "little")
            artifact.write_bytes(header)
            artifact.chmod(0o755)
            selection = build / "selection.json"
            selection.write_text(json.dumps({
                "artifact": str(artifact), "command": [str(artifact)],
                "workdir": str(source), "env": {},
            }))
            scope = {"__name__": "meson_smoke_fixture"}
            exec(VERIFY_MESON_NATIVE_TEST, scope)
            with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as run:
                scope["verify_meson_native_test"](build, source, selection)
            self.assertEqual(run.call_args.args[0], [str(artifact)])
            self.assertEqual(run.call_args.kwargs["cwd"], source)
            header[18:20] = (62).to_bytes(2, "little")
            artifact.write_bytes(header)
            with patch("subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "not AArch64"):
                    scope["verify_meson_native_test"](build, source, selection)
                run.assert_not_called()

    def test_google_test_source_path_is_conditional_and_shell_valid(self):
        self.assertIn(
            "[ -f /usr/src/googletest/googlemock/CMakeLists.txt ]",
            BUILD_AND_SMOKE,
        )
        self.assertIn("cp -a /src/. /work/src/", BUILD_AND_SMOKE)
        self.assertIn("set -- \"$@\" -DGOOGLETEST_PATH=/usr/src/googletest", BUILD_AND_SMOKE)
        self.assertIn(
            "set -- \"$@\" -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=/usr/src/googletest",
            BUILD_AND_SMOKE,
        )
        self.assertIn("cmake -S /work/src", BUILD_AND_SMOKE)
        self.assertIn('-DFETCHCONTENT_FULLY_DISCONNECTED=ON "$@"', BUILD_AND_SMOKE)
        self.assertIn("verify_native_test.py", BUILD_AND_SMOKE)
        self.assertIn("--candidates /work/build /work/src > /work/candidates.txt", BUILD_AND_SMOKE)
        self.assertIn(
            '--standalone /work/build /work/src /work/selection.json "$candidate"',
            BUILD_AND_SMOKE,
        )
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

    def test_only_declared_benchmark_and_example_options_are_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "CMakeLists.txt").write_text(
                "option(RL_BUILD_BENCHMARKS \"benchmarks\" ON)\n"
                "option(BUILD_EXAMPLES \"examples\" ON)\n"
                "option(BUILD_TESTING \"tests\" ON)\n"
                "# option(FAKE_BUILD_BENCHMARKS \"comment\" ON)\n"
                "option(UNSAFE_BUILD_BENCHMARKS;echo \"bad\" ON)\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-c", SELECT_CMAKE_NONTEST_OPTIONS, directory],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["-DBUILD_EXAMPLES=OFF", "-DRL_BUILD_BENCHMARKS=OFF"],
        )

    def test_meson_uses_writable_isolated_source_copy(self):
        self.assertIn("cp -a /src/. /work/src/", MESON_BUILD_AND_SMOKE)
        self.assertIn("meson setup /work/build /work/src", MESON_BUILD_AND_SMOKE)
        self.assertIn(
            "select_meson_native_test.py /work/build /work/src",
            MESON_BUILD_AND_SMOKE,
        )

    def test_shell_reports_failed_stage_on_command_error(self):
        trap_line = next(
            line for line in BUILD_AND_SMOKE.splitlines() if line.startswith("trap ")
        )
        probe_script = "stage=configure\n" + trap_line + "\nfalse\n"
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
            with self.assertRaisesRegex(ValueError, "built standalone test executable is missing"):
                scope["select_native_test"](
                    build, source, None, standalone_target="unit"
                )
            (build / "unit").write_bytes(b"built")
            standalone = scope["select_native_test"](
                build, source, None, standalone_target="unit"
            )
            self.assertEqual(standalone, {
                "artifact": str(build / "unit"),
                "target": "unit",
                "kind": "standalone",
            })
            with self.assertRaisesRegex(ValueError, r"not a C/C\+\+ test candidate"):
                scope["select_native_test"](
                    build, source, None, standalone_target="other"
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
            with self.assertRaisesRegex(ValueError, r"not a C/C\+\+ test candidate"):
                scope["select_native_test"](
                    build, source, None, standalone_target="unit"
                )

    def test_standalone_selector_rejects_outside_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, build = root / "source", root / "build"
            reply = build / ".cmake/api/v1/reply"
            source.mkdir()
            reply.mkdir(parents=True)
            cpp = source / "test.cpp"
            cpp.write_text("int main() { return 0; }\n")
            (build / "compile_commands.json").write_text(json.dumps([{
                "directory": str(build), "file": str(cpp),
            }]))
            (reply / "index-fixture.json").write_text(json.dumps({
                "reply": {"codemodel-v2": {"jsonFile": "model.json"}}
            }))
            (reply / "model.json").write_text(json.dumps({
                "configurations": [{"targets": [{
                    "name": "tests", "jsonFile": "target.json",
                }]}]
            }))
            (reply / "target.json").write_text(json.dumps({
                "type": "EXECUTABLE",
                "compileGroups": [{"language": "CXX"}],
                "sources": [{"path": str(cpp), "compileGroupIndex": 0}],
                "artifacts": [{"path": "../outside"}],
            }))
            (root / "outside").write_bytes(b"built")
            scope = {"__name__": "selector_fixture"}
            exec(SELECT_NATIVE_TEST, scope)
            with self.assertRaisesRegex(ValueError, r"not a C/C\+\+ test candidate"):
                scope["select_native_test"](
                    build, source, None, standalone_target="tests"
                )

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

    def test_standalone_smoke_runs_one_listed_gtest_with_bounded_time(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            artifact = build / "rltests"
            header = bytearray(20)
            header[:4] = b"\x7fELF"
            header[5] = 1
            header[18:20] = (183).to_bytes(2, "little")
            artifact.write_bytes(header)
            artifact.chmod(0o755)
            selection = build / "selection.json"
            selection.write_text(json.dumps({
                "artifact": str(artifact), "target": "rltests",
                "kind": "standalone",
            }))
            scope = {"__name__": "smoke_fixture"}
            exec(VERIFY_NATIVE_TEST, scope)
            results = [
                subprocess.CompletedProcess([], 0,
                    "DisabledSuite.\n  DISABLED_Broken\nParserTest.\n  ValidInput\n", ""),
                subprocess.CompletedProcess([], 0,
                    "[ RUN      ] ParserTest.ValidInput\n"
                    "[       OK ] ParserTest.ValidInput (0 ms)\n"
                    "[  PASSED  ] 1 test.\n", ""),
            ]
            with patch("subprocess.run", side_effect=results) as run:
                scope["verify_native_test"](build, selection)
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args_list[0].args[0], [
                str(artifact), "--gtest_list_tests",
            ])
            self.assertEqual(run.call_args_list[0].kwargs["timeout"], 8)
            self.assertEqual(run.call_args_list[1].args[0], [
                str(artifact), "--gtest_filter=ParserTest.ValidInput",
                "--gtest_color=no",
            ])
            self.assertEqual(run.call_args_list[1].kwargs["timeout"], 30)

            results[1] = subprocess.CompletedProcess([], 0, "[  PASSED  ] 0 tests.\n", "")
            with patch("subprocess.run", side_effect=results):
                with self.assertRaisesRegex(ValueError, "did not pass one test"):
                    scope["verify_native_test"](build, selection)
            results[1] = subprocess.CompletedProcess([], 0,
                "[ RUN      ] OtherTest.Case\n"
                "[       OK ] OtherTest.Case (0 ms)\n"
                "[  PASSED  ] 1 test.\n", "")
            with patch("subprocess.run", side_effect=results):
                with self.assertRaisesRegex(ValueError, "did not pass one test"):
                    scope["verify_native_test"](build, selection)

    def test_standalone_smoke_requires_output_if_not_gtest(self):
        scope = {"__name__": "smoke_fixture"}
        exec(VERIFY_NATIVE_TEST, scope)
        artifact = Path("/work/build/tests")
        listing = subprocess.CompletedProcess([], 0, "", "")
        direct = subprocess.CompletedProcess([], 0, "native smoke passed\n", "")
        with patch("subprocess.run", side_effect=[listing, direct]) as run:
            scope["run_standalone_test"](artifact, artifact.parent)
        self.assertEqual(run.call_args_list[1].args[0], [str(artifact)])
        with patch("subprocess.run", side_effect=[listing, subprocess.CompletedProcess([], 0, "", "")]):
            with self.assertRaisesRegex(ValueError, "passing smoke"):
                scope["run_standalone_test"](artifact, artifact.parent)
        listing_with_success_text = subprocess.CompletedProcess(
            [], 0, "native smoke passed\n", ""
        )
        with patch("subprocess.run", side_effect=[
            listing_with_success_text, subprocess.CompletedProcess([], 0, "", ""),
        ]):
            with self.assertRaisesRegex(ValueError, "passing smoke"):
                scope["run_standalone_test"](artifact, artifact.parent)

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

    def test_missing_folly_header_is_not_mislabeled_as_missing_compiler(self):
        output = (
            "FTS_ARM_PREFLIGHT_STAGE:configure\n"
            "-- The CXX compiler identification is Clang 18.1.3\n"
            "CMake Error at CMakeLists.txt:91 (MESSAGE):\n"
            "  /src/../folly/folly/Conv.h not found\n"
            "  token=private-build-log-value\n"
            "FTS_ARM_PREFLIGHT_FAILED_STAGE:configure:1\n"
        )
        evidence = _failure_evidence(output, 1)
        self.assertEqual(
            evidence,
            "native_arm_failure:stage=configure;kind=missing_dependency;exit=1",
        )
        self.assertNotIn("private-build-log-value", evidence)

    def test_actual_missing_compiler_remains_distinct_from_dependency_failure(self):
        output = (
            "FTS_ARM_PREFLIGHT_STAGE:configure\n"
            "CMake Error at CMakeLists.txt:3 (project):\n"
            "  The CMAKE_CXX_COMPILER:\n"
            "    clang++\n"
            "  is not a full path and was not found in the PATH.\n"
            "FTS_ARM_PREFLIGHT_FAILED_STAGE:configure:1\n"
        )
        self.assertEqual(
            _failure_evidence(output, 1),
            "native_arm_failure:stage=configure;kind=compiler_unavailable;exit=1",
        )

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

    def test_meson_candidate_uses_its_own_cache_without_changing_cmake(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            meson_candidate = candidate("org/meson")
            meson_candidate.static.signals = ["standard_build:meson.build"]
            evidence = (
                f"native_arm_preflight:{MESON_PREFLIGHT_VERSION}:"
                f"meson_build_meson_test:{SHA}"
            )
            engine = ScoutEngine(config)
            try:
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = ArmPreflightResult(
                        True, "native_arm_build_and_meson_test_passed", evidence
                    )
                    self.assertEqual(
                        engine._preflight_arm_candidates([meson_candidate]), (1, 1)
                    )
                self.assertTrue(meson_candidate.architecture.compatible)
                self.assertIsNotNone(engine.store.get_arm_preflight(
                    "org/meson", SHA, "aarch64", MESON_PREFLIGHT_VERSION
                ))
                self.assertIsNone(engine.store.get_arm_preflight(
                    "org/meson", SHA, "aarch64", PREFLIGHT_VERSION
                ))
                repeated = candidate("org/meson")
                repeated.static.signals = ["standard_build:meson.build"]
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    self.assertEqual(engine._preflight_arm_candidates([repeated]), (0, 1))
                    runner.return_value.check.assert_not_called()
            finally:
                engine.close()

    def test_preflight_prefers_smaller_source_then_score(self):
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
                self.assertEqual(names, ["org/z-small", "org/a-large"])
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

    def test_recent_build_failure_on_previous_commit_does_not_use_probe_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            config["architecture"]["arm_preflight_max_per_scan"] = 1
            repeated = candidate("org/repeated")
            repeated.final_score = 99
            fresh = candidate("org/fresh")
            fresh.final_score = 60
            engine = ScoutEngine(config)
            try:
                engine.store.put_arm_preflight(
                    repeated.repo.full_name, "b" * 40,
                    "aarch64", PREFLIGHT_VERSION,
                    passed=False, reason="native_build_or_smoke_failed",
                    evidence="native_arm_failure:stage=configure;kind=configure_failed;exit=1",
                )
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = ArmPreflightResult(
                        False, "native_build_or_smoke_failed"
                    )
                    self.assertEqual(
                        engine._preflight_arm_candidates([repeated, fresh]), (1, 0)
                    )
                    self.assertEqual(
                        [call.args[0].full_name for call in runner.return_value.check.call_args_list],
                        ["org/fresh"],
                    )
                self.assertIsNone(engine.store.get_arm_preflight(
                    repeated.repo.full_name, SHA, "aarch64", PREFLIGHT_VERSION,
                ))
                self.assertFalse(repeated.architecture.compatible)

                engine.store.connection.execute(
                    "UPDATE arm_preflight_cache SET checked_at=? WHERE full_name=?",
                    (
                        (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(),
                        repeated.repo.full_name,
                    ),
                )
                engine.store.connection.commit()
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = ArmPreflightResult(
                        False, "native_build_or_smoke_failed"
                    )
                    self.assertEqual(
                        engine._preflight_arm_candidates([repeated]), (1, 0)
                    )
                    runner.return_value.check.assert_called_once()
            finally:
                engine.close()

    def test_transient_failure_on_previous_commit_does_not_block_new_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            fresh_commit = candidate("org/parser")
            engine = ScoutEngine(config)
            try:
                engine.store.put_arm_preflight(
                    fresh_commit.repo.full_name, "b" * 40,
                    "aarch64", PREFLIGHT_VERSION,
                    passed=False, reason="builder_unavailable",
                )
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = ArmPreflightResult(
                        False, "builder_unavailable"
                    )
                    self.assertEqual(
                        engine._preflight_arm_candidates([fresh_commit]), (1, 0)
                    )
                    runner.return_value.check.assert_called_once()
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
