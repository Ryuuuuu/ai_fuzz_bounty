from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.arm_preflight import (
    ArmPreflight,
    ArmPreflightResult,
    PREFLIGHT_VERSION,
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
