import unittest
from datetime import datetime, timezone

from fuzz_target_scout.models import RepoSnapshot
from fuzz_target_scout.scoring import assess_static


class ScoringTests(unittest.TestCase):
    def test_existing_harness_and_local_build_rank_well(self):
        candidate = RepoSnapshot(
            full_name="org/parser",
            html_url="https://github.com/org/parser",
            default_branch="main",
            head_sha="abc",
            description="Small command-line parsing library for Linux",
            language="Rust",
            stars=100,
            size_kb=20_000,
            pushed_at=datetime.now(timezone.utc).isoformat(),
            paths=[
                "Cargo.toml",
                "src/lib.rs",
                "src/parser.rs",
                "tests/corpus/sample.bin",
                "fuzz/Cargo.toml",
                "fuzz/fuzz_targets/parse.rs",
            ],
            readme_excerpt="Build on Linux with cargo test.",
        )
        result = assess_static(candidate)
        self.assertGreaterEqual(result.fuzz_score, 80)
        self.assertLessEqual(result.reproduce_difficulty, 2)
        self.assertEqual(result.suggested_entry_kind, "existing_harness")

    def test_service_monorepo_is_harder(self):
        candidate = RepoSnapshot(
            full_name="org/cloud",
            html_url="https://github.com/org/cloud",
            default_branch="main",
            head_sha="abc",
            description="Kubernetes cloud service monorepo backed by database server",
            language="Go",
            size_kb=500_000,
            pushed_at=datetime.now(timezone.utc).isoformat(),
            paths=["go.mod"] + [f"services/s{i}/main.go" for i in range(5000)],
            readme_excerpt="Deploy a Kubernetes cluster and database server.",
        )
        result = assess_static(candidate)
        self.assertEqual(result.reproduce_difficulty, 5)
        self.assertIn("very_large_repository", result.blockers)


if __name__ == "__main__":
    unittest.main()
