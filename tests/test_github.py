import unittest

from fuzz_target_scout.github import _infer_fuzzable_language


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
