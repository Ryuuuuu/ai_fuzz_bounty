import unittest
from types import SimpleNamespace

from fuzz_target_scout.engine import ScoutEngine
from fuzz_target_scout.models import RepoSnapshot


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


if __name__ == "__main__":
    unittest.main()
