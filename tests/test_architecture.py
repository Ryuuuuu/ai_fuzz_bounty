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

    def test_portable_root_build_with_fuzz_harness_requires_real_native_probe(self):
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
        self.assertFalse(result.compatible)
        self.assertEqual(result.confidence, 50)
        self.assertEqual(
            result.blockers, ["native_build_probe_required:aarch64"]
        )
        self.assertEqual(result.evidence, [])

    def test_root_cmake_without_fuzz_harness_requires_real_probe(self):
        repo = RepoSnapshot(
            full_name="org/parser",
            html_url="https://github.com/org/parser",
            default_branch="main",
            head_sha="a" * 40,
            paths=["CMakeLists.txt", "src/parser.cc", "tests/parser_test.cc"],
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
        self.assertEqual(result.blockers, ["native_build_probe_required:aarch64"])

    def test_nested_cmake_does_not_request_root_probe(self):
        repo = RepoSnapshot(
            full_name="org/parser",
            html_url="https://github.com/org/parser",
            default_branch="main",
            head_sha="a" * 40,
            paths=["src/CMakeLists.txt", "src/parser.cc"],
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
        self.assertEqual(
            result.blockers, ["no_explicit_native_support_evidence:aarch64"]
        )

    def test_other_root_builds_do_not_request_cmake_probe(self):
        for marker in ("meson.build", "configure.ac"):
            with self.subTest(marker=marker):
                repo = RepoSnapshot(
                    full_name="org/parser",
                    html_url="https://github.com/org/parser",
                    default_branch="main",
                    head_sha="a" * 40,
                    paths=[marker, "src/parser.cc"],
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
                self.assertEqual(
                    result.blockers, ["no_explicit_native_support_evidence:aarch64"]
                )

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
