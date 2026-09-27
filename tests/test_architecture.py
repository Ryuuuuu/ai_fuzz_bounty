import unittest

from fuzz_target_scout.architecture import (
    assess_architecture,
    normalize_architecture,
)
from fuzz_target_scout.models import RepoSnapshot


class ArchitectureTests(unittest.TestCase):
    def test_arm64_ci_evidence_allows_native_host(self):
        repo = RepoSnapshot(
            full_name="org/parser",
            html_url="https://github.com/org/parser",
            default_branch="main",
            head_sha="a" * 40,
            architecture_files={
                ".github/workflows/build.yml": (
                    "strategy:\n  matrix:\n    platform: [linux/amd64, linux/arm64]\n"
                )
            },
        )
        result = assess_architecture(
            repo,
            {
                "mode": "native_only",
                "host_arch": "aarch64",
                "require_explicit_support": True,
            },
        )
        self.assertTrue(result.compatible)
        self.assertEqual(result.host_arch, "aarch64")
        self.assertTrue(result.evidence)

    def test_portable_root_build_with_fuzz_harness_allows_native_probe(self):
        repo = RepoSnapshot(
            full_name="org/parser",
            html_url="https://github.com/org/parser",
            default_branch="main",
            head_sha="a" * 40,
            paths=["CMakeLists.txt", "src/parser.cc", "fuzz/parser_fuzzer.cc"],
        )
        result = assess_architecture(
            repo,
            {
                "mode": "native_only",
                "host_arch": "arm64",
                "require_explicit_support": True,
                "allow_portable_native_probe": True,
            },
        )
        self.assertTrue(result.compatible)
        self.assertEqual(result.confidence, 60)
        self.assertIn("native_build_probe", result.evidence[0])

    def test_portable_probe_rejects_vendored_fuzz_harness(self):
        repo = RepoSnapshot(
            full_name="org/parser",
            html_url="https://github.com/org/parser",
            default_branch="main",
            head_sha="a" * 40,
            paths=["CMakeLists.txt", "third_party/lib/fuzz/fuzzer.cc"],
        )
        result = assess_architecture(
            repo,
            {
                "mode": "native_only",
                "host_arch": "arm64",
                "require_explicit_support": True,
                "allow_portable_native_probe": True,
            },
        )
        self.assertFalse(result.compatible)

    def test_missing_explicit_evidence_is_rejected(self):
        repo = RepoSnapshot(
            full_name="org/parser",
            html_url="https://github.com/org/parser",
            default_branch="main",
            head_sha="a" * 40,
            readme_excerpt="Build this portable C library on Linux.",
        )
        result = assess_architecture(
            repo,
            {
                "mode": "native_only",
                "host_arch": "arm64",
                "require_explicit_support": True,
            },
        )
        self.assertFalse(result.compatible)
        self.assertIn(
            "no_explicit_native_support_evidence:aarch64", result.blockers
        )

    def test_architecture_aliases_are_normalized(self):
        self.assertEqual(normalize_architecture("ARM64"), "aarch64")
        self.assertEqual(normalize_architecture("amd64"), "x86_64")


if __name__ == "__main__":
    unittest.main()
