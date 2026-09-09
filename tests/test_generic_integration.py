import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.generic_integration import (
    _dockerfile,
    _build_script,
    create_generic_project,
    detect_build_system,
    repair_generic_harness,
)


class GenericIntegrationTests(unittest.TestCase):
    def test_builder_installs_only_the_selected_build_family(self):
        dockerfile = _dockerfile("cmake")
        self.assertIn("cmake ninja-build pkg-config", dockerfile)
        self.assertNotIn("cargo", dockerfile)
        self.assertNotIn("autoconf", dockerfile)

    def test_native_builder_uses_multi_arch_ubuntu_and_clang(self):
        dockerfile = _dockerfile("cmake", "ubuntu:24.04")
        self.assertIn("FROM ubuntu:24.04", dockerfile)
        self.assertIn("clang lld llvm", dockerfile)
        self.assertIn("COPY --chmod=0644 generic_harness.cc", dockerfile)
        self.assertNotIn("gcr.io/oss-fuzz-base", dockerfile)

    def test_detects_all_supported_build_families(self):
        markers = {
            "cmake": "CMakeLists.txt",
            "meson": "meson.build",
            "autotools": "configure.ac",
            "cargo": "Cargo.toml",
        }
        for expected, marker in markers.items():
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                source = Path(directory)
                (source / marker).write_text("project")
                self.assertEqual(detect_build_system(source), expected)
                script = _build_script(expected)
                self.assertIn("$LIB_FUZZING_ENGINE", script)
                self.assertIn("$OUT/generic_fuzzer", script)
                harness_line = next(
                    line for line in script.splitlines()
                    if '"$SRC/generic_harness.cc"' in line
                )
                self.assertTrue(harness_line.endswith("\\"))
                self.assertFalse(harness_line.endswith("\\n"))
                self.assertTrue(
                    any(
                        line.startswith("  -Wl,--start-group")
                        for line in script.splitlines()
                    )
                )

    def test_reuses_existing_harness_without_ai(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            project = root / "oss-fuzz-project"
            (root / "artifacts").mkdir()
            source.mkdir()
            (source / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)")
            (source / "fuzz.cc").write_text(
                '#include <cstddef>\n#include <cstdint>\nextern "C" int '
                'LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }\n'
            )
            result = create_generic_project(
                job_dir=root, source=source, project_dir=project,
                project_name="fts-test", pipeline={},
            )
            self.assertEqual(result["build_system"], "cmake")
            self.assertTrue(result["harness_origin"].startswith("existing:"))
            self.assertEqual(result["candidate"]["file"], "fuzz.cc")
            self.assertEqual(
                (project / "generic_harness.cc").stat().st_mode & 0o777, 0o644
            )
            for name in ("Dockerfile", "build.sh", "project.yaml", "generic_harness.cc"):
                self.assertTrue((project / name).is_file())

    def test_repair_uses_bounded_compile_feedback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            project = root / "project"
            artifacts = root / "artifacts"
            mirror = root / "integration" / "oss-fuzz"
            for path in (source, project, artifacts, mirror):
                path.mkdir(parents=True, exist_ok=True)
            (source / "api.h").write_text("int parse_bytes(const char*, size_t);\n")
            (project / "generic_harness.cc").write_text(
                '#include <cstddef>\n#include <cstdint>\nextern "C" int '
                'LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }\n'
            )
            (artifacts / "generic-integration.json").write_text(
                '{"project":"fts-test","candidate":{},"repair_attempts":[]}'
            )
            response = '''```cpp
#include <cstddef>
#include <cstdint>
int parse_bytes(const char*, size_t);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  parse_bytes(reinterpret_cast<const char*>(data), size);
  return 0;
}
```'''
            with patch(
                "fuzz_target_scout.generic_integration.invoke_oss_fuzz_gen_adapter",
                return_value=(response, {"input_tokens": 1}),
            ):
                result = repair_generic_harness(
                    job_dir=root, source=source, project_dir=project,
                    pipeline={}, build_error="compiler error", attempt=1,
                )
            self.assertEqual(result["attempt"], 1)
            self.assertIn("parse_bytes", (project / "generic_harness.cc").read_text())


if __name__ == "__main__":
    unittest.main()
