import base64
import unittest

from fuzz_target_scout.github import GitHubClient, _infer_fuzzable_language


class GitHubRepositoryFileTests(unittest.TestCase):
    def test_repository_file_uses_contents_api_and_decodes_text(self):
        client = GitHubClient(
            {
                "api_url": "https://api.github.com",
                "timeout_seconds": 10,
                "max_tree_paths": 100,
            }
        )
        captured = {}

        def request(path):
            captured["path"] = path
            return {
                "encoding": "base64",
                "content": base64.b64encode(b"scope feed").decode(),
            }

        client._request = request
        result = client.get_repository_file(
            "google/bughunters",
            "oss-repository-tier/external_repositories.txtpb",
        )

        self.assertEqual(result, "scope feed")
        self.assertIn("/repos/google/bughunters/contents/", captured["path"])

    def test_repository_search_can_start_from_a_rotating_page(self):
        client = GitHubClient(
            {
                "api_url": "https://api.github.com",
                "timeout_seconds": 10,
                "max_tree_paths": 100,
            }
        )
        captured = {}

        def request(path):
            captured["path"] = path
            return {"items": []}

        client._request = request
        client.search_repositories("language:C", 20, start_page=7)

        self.assertIn("page=7", captured["path"])


class GitHubLanguageInferenceTests(unittest.TestCase):
    def test_native_fuzz_target_overrides_repository_size_language(self):
        paths = [
            "js/index.ts",
            "js/decoder.ts",
            "CMakeLists.txt",
            "c/common/constants.c",
            "c/dec/decode.c",
            "c/fuzz/decode_fuzzer.c",
        ]

        self.assertEqual(_infer_fuzzable_language(paths, "TypeScript"), "C")

    def test_vendored_native_sources_do_not_override_reported_language(self):
        paths = [
            "src/index.ts",
            "CMakeLists.txt",
            "third_party/library/a.c",
            "third_party/library/b.c",
            "third_party/library/c.c",
            "third_party/library/d.c",
            "third_party/library/e.c",
        ]

        self.assertEqual(_infer_fuzzable_language(paths, "TypeScript"), "TypeScript")

    def test_reported_language_is_preserved_without_native_fuzz_or_build_signal(self):
        self.assertEqual(
            _infer_fuzzable_language(["src/main.rs", "tests/parser_test.rs"], "Rust"),
            "Rust",
        )


if __name__ == "__main__":
    unittest.main()
