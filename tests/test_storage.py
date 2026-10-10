import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.central_agent import CentralAgent
from fuzz_target_scout.config import load_config
from fuzz_target_scout.models import (
    ArchitectureAssessment,
    Candidate,
    PolicyAssessment,
    RepoSnapshot,
    StaticAssessment,
)
from fuzz_target_scout.storage import Store


class StorageTests(unittest.TestCase):
    def test_search_cursor_rotates_and_resets_after_an_empty_page(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "scout.sqlite3")
            query = "language:C"
            self.assertEqual(store.get_search_page(query, 3), 1)
            store.advance_search_page(query, 1, had_results=True, max_pages=3)
            self.assertEqual(store.get_search_page(query, 3), 2)
            store.advance_search_page(query, 2, had_results=True, max_pages=3)
            self.assertEqual(store.get_search_page(query, 3), 3)
            store.advance_search_page(query, 3, had_results=True, max_pages=3)
            self.assertEqual(store.get_search_page(query, 3), 1)
            store.advance_search_page(query, 1, had_results=False, max_pages=3)
            self.assertEqual(store.get_search_page(query, 3), 1)
            store.close()

    def test_preflight_history_distinguishes_failure_and_meson_success(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "scout.sqlite3")
            version = "probe-v2"
            old_sha = "a" * 40
            new_sha = "b" * 40
            self.assertFalse(
                store.has_prior_failed_arm_preflight("org/parser", "aarch64")
            )
            store.put_arm_preflight(
                "org/parser", old_sha, "aarch64", "probe-v1",
                passed=False, reason="native_build_or_smoke_failed",
            )
            self.assertTrue(
                store.has_prior_failed_arm_preflight("ORG/PARSER", "aarch64")
            )
            store.put_arm_preflight(
                "org/parser", old_sha, "aarch64", version,
                passed=True, reason="native_arm_build_and_meson_test_passed",
                evidence=f"native_arm_preflight:{version}:meson_build_meson_test:{old_sha}",
            )
            self.assertTrue(
                store.has_prior_successful_arm_preflight(
                    "org/parser", new_sha, "aarch64", version
                )
            )
            self.assertFalse(
                store.has_prior_successful_arm_preflight(
                    "org/parser", old_sha, "aarch64", version
                )
            )
            store.close()

    def test_revalidation_backlog_filters_history_policy_language_score_and_arm(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "scout.sqlite3")
            scan_id = store.start_scan("test")

            def add(name, *, score=80, status="verified", language="C++", arm=True):
                store.upsert_candidate(
                    Candidate(
                        repo=RepoSnapshot(
                            full_name=name,
                            html_url=f"https://github.com/{name}",
                            default_branch="main",
                            head_sha="a" * 40,
                            language=language,
                            security_url=f"https://github.com/{name}/security/policy",
                        ),
                        static=StaticAssessment(
                            fuzz_score=score,
                            reproduce_difficulty=1,
                            signals=[],
                            blockers=[],
                            suggested_entry_kind="library_api",
                        ),
                        policy=PolicyAssessment(
                            status=status,
                            confidence=85,
                            source="security.md",
                            program_url="https://hackerone.com/example",
                            note="test",
                        ),
                        final_score=score,
                        architecture=ArchitectureAssessment(
                            host_arch="aarch64", compatible=arm, confidence=90
                        ),
                    ),
                    scan_id,
                )

            add("org/aa-selected")
            add("org/bb-fresh")
            add("org/cc-fresh")
            add("org/dd-low", score=54)
            add("org/ee-conditional", status="conditional")
            add("org/ff-rust", language="Rust")
            add("org/gg-no-arm", arm=False)
            names = store.revalidation_backlog_names(
                55, ["C", "C++"], {"ORG/AA-SELECTED"}, 2
            )
            self.assertEqual(names, ["org/bb-fresh", "org/cc-fresh"])
            self.assertEqual(
                store.revalidation_backlog_names(55, ["Rust"], set(), 2), []
            )
            store.close()

    def test_revalidation_backlog_seeds_exact_arm_probe_shapes_by_score_and_size(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "scout.sqlite3")
            scan_id = store.start_scan("test")

            def add(
                name, *, score=90, size_kb=1000, source_tree_kb=None, compatible=False,
                blockers=None, signals=None, status="verified", language="C++",
                program_url="https://hackerone.com/example", security_url=None,
            ):
                store.upsert_candidate(
                    Candidate(
                        repo=RepoSnapshot(
                            full_name=name,
                            html_url=f"https://github.com/{name}",
                            default_branch="main",
                            head_sha="a" * 40,
                            language=language,
                            size_kb=size_kb,
                            source_tree_kb=source_tree_kb,
                            security_url=(
                                f"https://github.com/{name}/security/policy"
                                if security_url is None else security_url
                            ),
                        ),
                        static=StaticAssessment(
                            fuzz_score=score,
                            reproduce_difficulty=1,
                            signals=(
                                ["standard_build:cmakelists.txt"]
                                if signals is None else signals
                            ),
                            blockers=[],
                            suggested_entry_kind="library_api",
                        ),
                        policy=PolicyAssessment(
                            status=status,
                            confidence=85,
                            source="security.md",
                            program_url=program_url,
                            note="test",
                        ),
                        final_score=score,
                        architecture=ArchitectureAssessment(
                            host_arch="aarch64", compatible=compatible,
                            confidence=90, blockers=blockers or [],
                        ),
                    ),
                    scan_id,
                )

            add("org/compatible", score=95, compatible=True, signals=[])
            add("org/probe-small", size_kb=500, blockers=["native_build_probe_required:aarch64"])
            add("org/no-evidence", size_kb=1500, blockers=["no_explicit_native_support_evidence:aarch64"])
            add("org/probe-large", size_kb=3000, blockers=["native_build_probe_required:aarch64"])
            add("org/extra-blocker", score=99, blockers=["native_build_probe_required:aarch64", "unsupported:aarch64"])
            add("org/other-arm", score=99, blockers=["no_explicit_native_support_evidence:x86_64"])
            add("org/nested-cmake", score=99, blockers=["native_build_probe_required:aarch64"], signals=["standard_build:src/cmakelists.txt"])
            add("org/other-build", score=99, blockers=["native_build_probe_required:aarch64"], signals=["standard_build:makefile"])
            add("org/meson", score=80, blockers=["native_build_probe_required:aarch64"], signals=["standard_build:MeSoN.BuIlD"])
            add("org/meson-conditional", score=80, status="conditional", blockers=["native_build_probe_required:aarch64"], signals=["standard_build:meson.build"])
            add("org/meson-low", score=54, blockers=["native_build_probe_required:aarch64"], signals=["standard_build:meson.build"])
            add("org/meson-rust", score=80, language="Rust", blockers=["native_build_probe_required:aarch64"], signals=["standard_build:meson.build"])
            add("org/no-program", score=99, blockers=["native_build_probe_required:aarch64"], program_url="")
            add("org/no-security", score=99, blockers=["native_build_probe_required:aarch64"], security_url="")
            add("org/conditional", score=99, status="conditional", blockers=["native_build_probe_required:aarch64"])
            add("org/rust", score=99, language="Rust", blockers=["native_build_probe_required:aarch64"])
            add("org/low", score=54, blockers=["native_build_probe_required:aarch64"])
            add("org/no-size", score=99, size_kb=0, blockers=["native_build_probe_required:aarch64"])
            add("org/oversize", score=99, size_kb=100_001, blockers=["native_build_probe_required:aarch64"])
            store.connection.execute(
                "UPDATE candidates SET last_seen_at=?",
                ("2025-01-01T00:00:00+00:00",),
            )
            store.connection.commit()

            self.assertEqual(
                store.revalidation_backlog_names(55, ["C", "C++"], set(), 3),
                ["org/compatible", "org/probe-small", "org/no-evidence"],
            )
            self.assertEqual(
                store.revalidation_backlog_names(
                    55, ["C++"], {"ORG/COMPATIBLE", "ORG/PROBE-SMALL"}, 2
                ),
                ["org/no-evidence", "org/probe-large"],
            )
            store.connection.execute(
                "UPDATE candidates SET last_seen_at=? WHERE full_name IN (?, ?)",
                ("2025-01-02T00:00:00+00:00", "org/compatible", "org/probe-small"),
            )
            store.connection.commit()
            self.assertEqual(
                store.revalidation_backlog_names(55, ["C++"], set(), 2),
                ["org/no-evidence", "org/probe-large"],
            )
            self.assertEqual(
                store.revalidation_backlog_names(
                    55, ["C++"],
                    {"org/compatible", "org/probe-small", "org/no-evidence", "org/probe-large"},
                    2,
                ),
                ["org/meson"],
            )
            self.assertEqual(
                store.revalidation_backlog_names(
                    55, ["C++"],
                    {"org/compatible", "org/probe-small", "org/no-evidence", "org/probe-large", "ORG/MESON"},
                    2,
                ),
                [],
            )
            add(
                "org/tree-small", size_kb=221_733, source_tree_kb=35_000,
                blockers=["native_build_probe_required:aarch64"],
            )
            self.assertEqual(
                store.revalidation_backlog_names(
                    55, ["C++"],
                    {"org/compatible", "org/probe-small", "org/no-evidence", "org/probe-large", "org/meson"},
                    1,
                ),
                ["org/tree-small"],
            )
            store.close()

    def test_export_gate_excludes_conditional_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "scout.sqlite3")
            scan_id = store.start_scan("test")
            for name, status in (("org/public", "verified"), ("org/invite", "conditional")):
                candidate = Candidate(
                    repo=RepoSnapshot(
                        full_name=name,
                        html_url=f"https://github.com/{name}",
                        default_branch="main",
                        head_sha="abc",
                        language="C",
                        security_url=f"https://github.com/{name}/security/policy",
                        security_text="policy",
                    ),
                    static=StaticAssessment(
                        fuzz_score=80,
                        reproduce_difficulty=2,
                        signals=["existing_fuzz_assets:2"],
                        blockers=[],
                        suggested_entry_kind="existing_harness",
                    ),
                    policy=PolicyAssessment(
                        status=status,
                        confidence=100,
                        source="catalog",
                        program_url="https://hackerone.com/example",
                        note="test",
                    ),
                    final_score=80,
                )
                store.upsert_candidate(candidate, scan_id)
            rows = list(store.export_rows(50, include_conditional=False))
            self.assertEqual([row["repository"] for row in rows], ["org/public"])
            serialized = json.dumps(rows[0])
            self.assertNotIn("security_text", serialized)
            store.close()


    def test_export_gate_excludes_disabled_languages(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "scout.sqlite3")
            scan_id = store.start_scan("test")
            for name, language in (
                ("org/native", "C++"),
                ("org/go-tool", "Go"),
                ("org/rust-tool", "Rust"),
            ):
                candidate = Candidate(
                    repo=RepoSnapshot(
                        full_name=name,
                        html_url=f"https://github.com/{name}",
                        default_branch="main",
                        head_sha="abc",
                        language=language,
                        security_url=f"https://github.com/{name}/security/policy",
                        security_text="policy",
                    ),
                    static=StaticAssessment(
                        fuzz_score=80,
                        reproduce_difficulty=2,
                        signals=["test"],
                        blockers=[],
                        suggested_entry_kind="existing_harness",
                    ),
                    policy=PolicyAssessment(
                        status="verified",
                        confidence=100,
                        source="catalog",
                        program_url="https://hackerone.com/example",
                        note="test",
                    ),
                    final_score=80,
                )
                store.upsert_candidate(candidate, scan_id)
            rows = list(
                store.export_rows(50, False, enabled_languages=["C", "C++"])
            )
            store.close()

        self.assertEqual([row["repository"] for row in rows], ["org/native"])


    def test_central_export_uses_current_scan_and_preserves_candidate_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["architecture"]["mode"] = "native_only"
            config["storage"]["database_path"] = str(root / "scout.sqlite3")
            config["storage"]["export_path"] = str(root / "verified.jsonl")
            store = Store(config["storage"]["database_path"])

            def candidate(name, *, status="verified", compatible=True):
                return Candidate(
                    repo=RepoSnapshot(
                        full_name=name,
                        html_url=f"https://github.com/{name}",
                        default_branch="main",
                        head_sha="a" * 40,
                        language="C",
                        security_url=f"https://github.com/{name}/security/policy",
                        security_text="policy",
                    ),
                    static=StaticAssessment(
                        fuzz_score=80,
                        reproduce_difficulty=2,
                        signals=["standard_build:cmakelists.txt"],
                        blockers=[],
                        suggested_entry_kind="existing_harness",
                    ),
                    policy=PolicyAssessment(
                        status=status,
                        confidence=100,
                        source="catalog",
                        program_url="https://hackerone.com/example",
                        note="test",
                    ),
                    final_score=80,
                    architecture=ArchitectureAssessment(
                        host_arch="aarch64",
                        compatible=compatible,
                        confidence=90,
                    ),
                )

            first_scan = store.start_scan("test")
            store.upsert_candidate(candidate("org/previous"), first_scan)
            store.finish_scan(first_scan, "completed", 1, 1)
            second_scan = store.start_scan("test")
            store.upsert_candidate(candidate("org/current"), second_scan)
            store.upsert_candidate(
                candidate("org/wrong-architecture", compatible=False), second_scan
            )
            store.upsert_candidate(
                candidate("org/conditional", status="conditional"), second_scan
            )
            store.finish_scan(second_scan, "completed", 3, 2)

            historical = list(store.export_rows(50, False))
            scoped = list(store.export_rows(50, False, scan_id=second_scan))
            store.close()
            self.assertEqual(len(historical), 3)
            self.assertEqual(
                {row["repository"] for row in scoped},
                {"org/current", "org/wrong-architecture"},
            )

            CentralAgent(config)._export_verified_candidates(second_scan)
            exported = [
                json.loads(line)
                for line in Path(config["storage"]["export_path"]).read_text().splitlines()
            ]
            self.assertEqual([row["repository"] for row in exported], ["org/current"])

    def test_failed_discovery_preserves_previous_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            output = root / "verified.jsonl"
            output.write_text("previous export\n", encoding="utf-8")
            config["storage"]["export_path"] = str(output)
            agent = CentralAgent(config)

            with patch("fuzz_target_scout.central_agent.ScoutEngine") as engine, patch.object(
                agent, "_notify"
            ):
                engine.return_value.scan.side_effect = RuntimeError("discovery failed")
                agent._refresh_candidates_if_due()

            self.assertEqual(output.read_text(encoding="utf-8"), "previous export\n")
            self.assertIn("discovery failed", agent.state["last_discovery_error"])

if __name__ == "__main__":
    unittest.main()
