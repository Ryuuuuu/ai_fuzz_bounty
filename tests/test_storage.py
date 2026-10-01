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
