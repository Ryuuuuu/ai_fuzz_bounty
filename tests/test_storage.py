import json
import tempfile
import unittest
from pathlib import Path

from fuzz_target_scout.models import (
    Candidate,
    PolicyAssessment,
    RepoSnapshot,
    StaticAssessment,
)
from fuzz_target_scout.storage import Store


class StorageTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
