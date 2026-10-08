import copy
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fuzz_target_scout.config import load_config
from fuzz_target_scout.engine import ScoutEngine
from fuzz_target_scout.github import GitHubError
from fuzz_target_scout.models import (
    AIAssessment, ArchitectureAssessment, Candidate, PolicyAssessment,
    RepoSnapshot, StaticAssessment,
)


class _SearchStore:
    def __init__(self):
        self.page = 1

    def get_search_page(self, _query, _max_pages):
        return self.page

    def advance_search_page(self, _query, current_page, *, had_results, max_pages):
        self.page = current_page + 1 if had_results and current_page < max_pages else 1


class _SearchGitHub:
    def __init__(self):
        self.pages = []

    def search_repositories(self, _query, _limit, *, start_page):
        self.pages.append(start_page)
        return [
            RepoSnapshot(
                full_name=f"org/parser-{start_page}",
                html_url=f"https://github.com/org/parser-{start_page}",
                default_branch="main",
                head_sha="a" * 40,
                language="C++",
            )
        ]


class EngineIdleDiscoveryTests(unittest.TestCase):
    def test_idle_preflight_stops_after_first_native_success(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            engine = ScoutEngine(config)
            first = Candidate(
                repo=RepoSnapshot(
                    full_name="org/parser-one", html_url="https://github.com/org/parser-one",
                    default_branch="main", head_sha="a" * 40,
                    language="C++", size_kb=100,
                    security_url="https://github.com/org/parser-one/security/policy",
                ),
                static=StaticAssessment(
                    fuzz_score=80, reproduce_difficulty=1,
                    signals=["standard_build:cmakelists.txt"],
                    blockers=["native_build_probe_required:aarch64"],
                    suggested_entry_kind="library_api",
                ),
                policy=PolicyAssessment(
                    status="verified", confidence=95, source="security.md",
                    program_url="https://hackerone.com/example",
                ),
                final_score=80,
                architecture=ArchitectureAssessment(
                    host_arch="aarch64", compatible=False, confidence=40,
                    blockers=["native_build_probe_required:aarch64"],
                ),
            )
            second = copy.deepcopy(first)
            second.repo.full_name = "org/parser-two"
            second.repo.head_sha = "b" * 40
            second.repo.html_url = "https://github.com/org/parser-two"
            try:
                with patch("fuzz_target_scout.engine.ArmPreflight") as runner:
                    runner.return_value.check.return_value = SimpleNamespace(
                        passed=True, reason="native_test_passed",
                        evidence="native_arm_preflight:test:cmake_build_ctest:" + "a" * 40,
                    )
                    attempted, passed = engine._preflight_arm_candidates(
                        [first, second], max_attempts=4,
                        stop_after_success=True,
                    )
                self.assertEqual((attempted, passed), (1, 1))
                runner.return_value.check.assert_called_once()
                self.assertTrue(first.architecture.compatible)
                self.assertFalse(second.architecture.compatible)
            finally:
                engine.close()

    def test_arm_preflight_idle_budget_limits_expensive_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            config["architecture"]["arm_preflight_failure_retry_hours"] = 0
            engine = ScoutEngine(config)

            def candidate(index):
                return Candidate(
                    repo=RepoSnapshot(
                        full_name=f"org/parser-{index}",
                        html_url=f"https://github.com/org/parser-{index}",
                        default_branch="main", head_sha=f"{index:x}" * 40,
                        language="C++", size_kb=100,
                        security_url=f"https://github.com/org/parser-{index}/security/policy",
                    ),
                    static=StaticAssessment(
                        fuzz_score=80, reproduce_difficulty=1,
                        signals=["standard_build:cmakelists.txt"],
                        blockers=["native_build_probe_required:aarch64"],
                        suggested_entry_kind="library_api",
                    ),
                    policy=PolicyAssessment(
                        status="verified", confidence=95, source="security.md",
                        program_url="https://hackerone.com/example",
                    ),
                    final_score=80,
                    architecture=ArchitectureAssessment(
                        host_arch="aarch64", compatible=False, confidence=40,
                        blockers=["native_build_probe_required:aarch64"],
                    ),
                )

            probes = [candidate(index) for index in range(1, 4)]
            try:
                with patch("fuzz_target_scout.engine.time.monotonic",
                           side_effect=[0, 1, 100]), patch(
                    "fuzz_target_scout.engine.ArmPreflight"
                ) as runner:
                    runner.return_value.check.return_value = SimpleNamespace(
                        passed=False, reason="native_build_or_smoke_failed",
                        evidence="native_arm_failure:stage=build;kind=missing_dependency;exit=1",
                    )
                    attempted, passed = engine._preflight_arm_candidates(
                        probes, max_attempts=3, budget_seconds=120,
                    )
                self.assertEqual((attempted, passed), (1, 0))
                self.assertEqual(runner.call_count, 1)
                self.assertEqual(
                    runner.call_args.args[0]["arm_preflight_timeout_seconds"], 119,
                )
            finally:
                engine.close()

    def test_readme_exclusion_rechecks_policy_after_code_hydration(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["github"]["seed_policy_catalog"] = False
            config["pipeline"]["languages"] = ["C++"]
            engine = ScoutEngine(config)
            engine.policy.entries = {}
            engine._refresh_policy_sources = lambda: None

            class GitHub:
                def get_repository(self, name):
                    return RepoSnapshot(
                        full_name=name,
                        html_url=f"https://github.com/{name}",
                        default_branch="main",
                        head_sha="a" * 40,
                        language="C++",
                        size_kb=1000,
                    )

                def load_security_policy(self, target):
                    return replace(
                        target,
                        security_url="https://github.com/facebookincubator/.github/blob/main/SECURITY.md",
                        security_text=(
                            "This project has a bug bounty program at "
                            "https://www.facebook.com/whitehat."
                        ),
                    )

                def hydrate_code_evidence(self, target):
                    return replace(
                        target,
                        readme_excerpt=(
                            "Issues are expected and are not eligible for bug bounty "
                            "or considered security findings."
                        ),
                    )

            engine.github = GitHub()
            try:
                summary = engine.scan(
                    queries=[], seed_repositories=["facebookincubator/bpfjailer"],
                    use_ai=False,
                )
                self.assertEqual((summary.verified, summary.rejected), (0, 1))
                self.assertEqual(
                    list(engine.store.export_rows(55, False, scan_id=summary.scan_id)),
                    [],
                )
            finally:
                engine.close()

    def test_seeded_repository_rechecks_current_policy_code_and_head(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["github"]["seed_policy_catalog"] = False
            config["github"]["queries"] = []
            config["pipeline"]["languages"] = ["C++"]
            engine = ScoutEngine(config)
            calls = []

            class GitHub:
                def get_repository(self, name):
                    calls.append(("repository", name))
                    if name == "org/error":
                        raise GitHubError("temporary API failure")
                    return RepoSnapshot(
                        full_name=name,
                        html_url=f"https://github.com/{name}",
                        default_branch="main",
                        head_sha="b" * 40,
                        language="C++",
                        security_url=f"https://github.com/{name}/security/policy",
                    )

                def load_security_policy(self, repo):
                    calls.append(("policy", repo.full_name))
                    return repo

                def hydrate_code_evidence(self, repo):
                    calls.append(("code", repo.full_name))
                    return repo

            engine.github = GitHub()
            engine._refresh_policy_sources = lambda: None
            try:
                def verify(repo):
                    status = "rejected" if repo.full_name == "org/stale" else "verified"
                    return PolicyAssessment(
                        status=status, confidence=85, source="security.md",
                        program_url="https://hackerone.com/example" if status == "verified" else "",
                        note="current policy",
                    )

                with patch.object(engine.policy, "verify", side_effect=verify), patch(
                    "fuzz_target_scout.engine.assess_architecture",
                    return_value=ArchitectureAssessment(
                        host_arch="aarch64", compatible=True, confidence=90
                    ),
                ), patch(
                    "fuzz_target_scout.engine.assess_static",
                    return_value=StaticAssessment(
                        fuzz_score=80, reproduce_difficulty=1, signals=[],
                        blockers=[], suggested_entry_kind="library_api",
                    ),
                ), patch("fuzz_target_scout.engine.final_score", return_value=80), patch.object(
                    engine, "_preflight_arm_candidates", return_value=(0, 0)
                ) as preflight, patch.object(
                    engine, "_apply_ai", return_value=(0, 0, 0)
                ):
                    summary = engine.scan(
                        queries=[], use_ai=False, run_arm_preflight=True,
                        seed_repositories=[
                            "org/excluded", "org/fresh", "org/stale", "org/error"
                        ],
                        exclude_repositories={"org/excluded"},
                    )

                self.assertEqual(summary.errors, 1)
                self.assertEqual(summary.discovered, 2)
                self.assertEqual(preflight.call_count, 1)
                self.assertNotIn(("repository", "org/excluded"), calls)
                self.assertIn(("policy", "org/fresh"), calls)
                self.assertIn(("policy", "org/stale"), calls)
                self.assertIn(("code", "org/fresh"), calls)
                self.assertNotIn(("code", "org/stale"), calls)
                rows = list(engine.store.export_rows(55, False, scan_id=summary.scan_id))
                self.assertEqual([row["repository"] for row in rows], ["org/fresh"])
                self.assertEqual(rows[0]["commit"], "b" * 40)
                stale = engine.store.connection.execute(
                    "SELECT policy_status, last_scan_id FROM candidates WHERE full_name=?",
                    ("org/stale",),
                ).fetchone()
                self.assertEqual((stale["policy_status"], stale["last_scan_id"]),
                                 ("rejected", summary.scan_id))
            finally:
                engine.close()

    def test_idle_search_advances_multiple_pages_without_replaying_old_page(self):
        engine = object.__new__(ScoutEngine)
        engine.config = {
            "github": {
                "seed_policy_catalog": False,
                "queries": ["org:example language:C++"],
                "additional_queries": [],
                "per_query": 20,
                "max_search_pages": 5,
            },
            "pipeline": {"languages": ["C++"]},
        }
        engine.policy = SimpleNamespace(catalog_names=[])
        engine.store = _SearchStore()
        engine.github = _SearchGitHub()
        engine.progress = lambda _message: None

        routine = engine._discover(False, None, None)
        expanded = engine._discover(False, None, None, search_pages_per_query=2)

        self.assertEqual([item.full_name for item in routine], ["org/parser-1"])
        self.assertEqual(
            [item.full_name for item in expanded],
            ["org/parser-2", "org/parser-3"],
        )
        self.assertEqual(engine.github.pages, [1, 2, 3])
        self.assertEqual(engine.store.page, 4)


class EngineCandidateReviewTests(unittest.TestCase):
    def test_arm_ai_review_uses_planner_native_build_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["architecture"]["host_arch"] = "aarch64"
            config["pipeline"]["architecture"]["host_arch"] = "aarch64"
            config["pipeline"]["runs_path"] = str(Path(directory) / "runs")
            engine = ScoutEngine(config)
            policy = PolicyAssessment(
                status="verified", confidence=95, source="security.md",
                program_url="https://example.com/bounty",
            )
            architecture = ArchitectureAssessment(
                host_arch="aarch64", compatible=True, confidence=90,
                evidence=["README:linux/arm64"],
            )

            def candidate(name, paths, signals):
                repo = RepoSnapshot(
                    full_name=name,
                    html_url=f"https://github.com/{name}",
                    default_branch="main",
                    head_sha="a" * 40,
                    language="C++",
                    paths=paths,
                    security_url=f"https://github.com/{name}/security/policy",
                )
                static = StaticAssessment(
                    fuzz_score=80, reproduce_difficulty=2,
                    signals=signals, blockers=[],
                    suggested_entry_kind="existing_harness",
                )
                return Candidate(
                    repo=repo, static=static, policy=policy,
                    final_score=80, architecture=architecture,
                )

            bazel_only = candidate(
                "cloudflare/workerd",
                ["BUILD.bazel", "src/parser.cc", "fuzz/parser.cc"],
                ["existing_fuzz_assets:1"],
            )
            root_cmake = candidate(
                "org/native-parser",
                ["CMakeLists.txt", "src/parser.cc", "fuzz/parser.cc"],
                ["standard_build:cmakelists.txt", "existing_fuzz_assets:1"],
            )
            reviewed = []

            def assess_batch(evidence_items):
                reviewed.extend(item["repository"] for item in evidence_items)
                return {
                    "org/native-parser": AIAssessment(
                        fuzz_score=80, reproduce_difficulty=2,
                        suggested_entry_kind="existing_harness",
                        rationale="local native build", blockers=[],
                    )
                }, {"input_tokens": 47, "cached_tokens": 0, "output_tokens": 13}

            reviewer = SimpleNamespace(
                available=True, model="test-model", prompt_version="test-v1",
                assess_batch=assess_batch,
            )
            try:
                with patch(
                    "fuzz_target_scout.engine.CodexReviewer", return_value=reviewer
                ):
                    self.assertEqual(
                        engine._apply_ai([bazel_only], True), (0, 0, 0)
                    )
                    self.assertEqual(reviewed, [])
                    calls, cache_hits, errors = engine._apply_ai(
                        [bazel_only, root_cmake], True
                    )
                self.assertEqual((calls, cache_hits, errors), (1, 0, 0))
                self.assertEqual(reviewed, ["org/native-parser"])
                self.assertIsNone(bazel_only.ai)
                self.assertIsNotNone(root_cmake.ai)
                cache_rows = engine.store.connection.execute(
                    "SELECT full_name, input_tokens FROM ai_cache"
                ).fetchall()
                self.assertEqual(
                    [(row["full_name"], row["input_tokens"]) for row in cache_rows],
                    [("org/native-parser", 47)],
                )
            finally:
                engine.close()


if __name__ == "__main__":
    unittest.main()
