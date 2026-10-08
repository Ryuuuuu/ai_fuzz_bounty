import base64
import http.client
import json
import unittest
from unittest.mock import patch

from fuzz_target_scout.github import GitHubClient, GitHubError, _infer_fuzzable_language


class GitHubRepositoryFileTests(unittest.TestCase):
    def test_transient_remote_disconnect_is_retried(self):
        client = GitHubClient(
            {
                "api_url": "https://api.github.com",
                "timeout_seconds": 10,
                "retry_attempts": 3,
                "retry_backoff_seconds": 0,
                "max_tree_paths": 100,
            }
        )

        class Response:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps({"ok": True}).encode()

        with patch(
            "fuzz_target_scout.github.urllib.request.urlopen",
            side_effect=[http.client.RemoteDisconnected(), Response()],
        ) as request:
            result = client._request("/rate_limit")

        self.assertEqual(result, {"ok": True})
        self.assertEqual(request.call_count, 2)

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

    def test_repository_without_own_policy_uses_owner_default(self):
        client = GitHubClient(
            {
                "api_url": "https://api.github.com",
                "timeout_seconds": 10,
                "max_tree_paths": 100,
            }
        )
        requested = []

        def request(path):
            requested.append(path)
            if "/repos/facebook/.github/contents/SECURITY.md?ref=main" in path:
                return {
                    "encoding": "base64",
                    "content": base64.b64encode(b"eligible for a bounty").decode(),
                }
            return None

        client._request = request
        repo = client._snapshot(
            {
                "full_name": "facebook/folly",
                "default_branch": "main",
                "language": "C++",
            }
        )
        result = client.load_security_policy(repo)

        self.assertEqual(result.security_text, "eligible for a bounty")
        self.assertEqual(
            result.security_url,
            "https://github.com/facebook/.github/blob/main/SECURITY.md",
        )
        self.assertTrue(any("facebook/.github" in path for path in requested))

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


class GitHubCodeEvidenceTests(unittest.TestCase):
    @staticmethod
    def _client_and_repo():
        client = GitHubClient(
            {
                "api_url": "https://api.github.com",
                "timeout_seconds": 10,
                "max_tree_paths": 100,
            }
        )
        repo = client._snapshot(
            {
                "full_name": "example/project",
                "default_branch": "release/v1",
                "language": "C++",
            }
        )
        return client, repo

    def test_code_evidence_uses_commit_sha_and_pins_tree_and_readme(self):
        client, repo = self._client_and_repo()
        commit_sha, tree_sha = "a" * 40, "b" * 40
        requested = []

        def request(path):
            requested.append(path)
            if path.endswith("/commits/release%2Fv1"):
                return {"sha": commit_sha, "commit": {"tree": {"sha": tree_sha}}}
            if path.endswith(f"/git/trees/{tree_sha}?recursive=1"):
                return {
                    "sha": tree_sha,
                    "tree": [{"path": "CMakeLists.txt", "type": "blob", "sha": "c" * 40}],
                }
            if path.endswith(f"/readme?ref={commit_sha}"):
                return {
                    "encoding": "base64",
                    "content": base64.b64encode(b"build with cmake").decode(),
                }
            return None

        client._request = request
        result = client.hydrate_code_evidence(repo)

        self.assertEqual(result.head_sha, commit_sha)
        self.assertNotEqual(result.head_sha, tree_sha)
        self.assertEqual(result.paths, ["CMakeLists.txt"])
        self.assertIn("build with cmake", result.readme_excerpt)
        self.assertTrue(any(path.endswith(f"/git/trees/{tree_sha}?recursive=1") for path in requested))
        self.assertTrue(any(path.endswith(f"/readme?ref={commit_sha}") for path in requested))
        self.assertEqual(sum("/commits/" in path for path in requested), 1)

    def test_missing_or_invalid_commit_fails_closed_without_using_prior_sha(self):
        client, repo = self._client_and_repo()
        repo.head_sha = "c" * 40
        invalid = (
            None,
            {},
            {"sha": "short", "commit": {"tree": {"sha": "b" * 40}}},
            {"sha": "a" * 40, "commit": {"tree": {"sha": "short"}}},
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                requested = []

                def request(path):
                    requested.append(path)
                    return payload

                client._request = request
                with self.assertRaises(GitHubError):
                    client.hydrate_code_evidence(repo)
                self.assertEqual(len(requested), 1)
                self.assertIn("/commits/", requested[0])

    def test_mismatched_tree_fails_closed(self):
        client, repo = self._client_and_repo()
        commit_sha, tree_sha = "a" * 40, "b" * 40

        def request(path):
            if "/commits/" in path:
                return {"sha": commit_sha, "commit": {"tree": {"sha": tree_sha}}}
            return {"sha": "c" * 40, "tree": []}

        client._request = request
        with self.assertRaisesRegex(GitHubError, "inconsistent tree"):
            client.hydrate_code_evidence(repo)


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
