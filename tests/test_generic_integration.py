import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.generic_integration import (
    _dockerfile,
    _build_script,
    _candidate_support_dependencies,
    _detect_source_dependencies,
    _detect_system_dependencies,
    _find_existing_harness,
    create_generic_project,
    detect_build_system,
    repair_generic_harness,
)


class GenericIntegrationTests(unittest.TestCase):
    def test_prefers_simple_public_harness_over_static_only_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            fuzz = source / "tests" / "fuzz"
            fuzz.mkdir(parents=True)
            (fuzz / "block_decompress.c").write_text(
                '#define LIB_STATIC_LINKING_ONLY\n'
                'int LLVMFuzzerTestOneInput(const unsigned char *data, '
                'unsigned long size) { return 0; }\n'
            )
            preferred = fuzz / "simple_decompress.c"
            preferred.write_text(
                'int LLVMFuzzerTestOneInput(const unsigned char *data, '
                'unsigned long size) { return 0; }\n'
            )

            self.assertEqual(_find_existing_harness(source), preferred)
            self.assertEqual(
                _find_existing_harness(
                    source, {"tests/fuzz/simple_decompress.c"}
                ),
                fuzz / "block_decompress.c",
            )

    def test_builder_installs_only_the_selected_build_family(self):
        dockerfile = _dockerfile("cmake")
        self.assertIn("cmake ninja-build pkg-config", dockerfile)
        self.assertIn("python3", dockerfile)
        self.assertNotIn("cargo", dockerfile)
        self.assertNotIn("autoconf", dockerfile)

    def test_native_builder_uses_multi_arch_ubuntu_and_clang(self):
        dockerfile = _dockerfile("cmake", "ubuntu:24.04")
        self.assertIn("FROM ubuntu:24.04", dockerfile)
        self.assertIn("clang lld llvm", dockerfile)
        self.assertIn("COPY --chmod=0644 generic_harness.cc", dockerfile)
        self.assertNotIn("gcr.io/oss-fuzz-base", dockerfile)

    def test_cmake_dependencies_are_inferred_from_a_reviewed_allow_list(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "CMakeLists.txt").write_text(
                "find_package(absl REQUIRED)\n"
                "find_package(OpenSSL REQUIRED)\n"
                "find_package(gflags REQUIRED)\n"
                "set(CPUINFO_SOURCE_DIR ignored)\n"
                "set(PTHREADPOOL_SOURCE_DIR ignored)\n"
                "find_package(attacker_controlled REQUIRED)\n"
            )
            dependencies = _detect_system_dependencies(source, "cmake")
            source_dependencies = _detect_source_dependencies(source, "cmake")
            dockerfile = _dockerfile(
                "cmake", "ubuntu:24.04", dependencies, source_dependencies
            )

        self.assertEqual(dependencies, ["libgflags-dev", "libssl-dev"])
        self.assertEqual(
            source_dependencies, ["absl", "cpuinfo", "fxdiv", "pthreadpool"]
        )
        self.assertIn("libgflags-dev libssl-dev git", dockerfile)
        self.assertIn("https://github.com/abseil/abseil-cpp.git", dockerfile)
        self.assertIn("d38452e1ee03523a208362186fd42248ff2609f6", dockerfile)
        self.assertIn("https://github.com/pytorch/cpuinfo.git", dockerfile)
        self.assertIn("8ce83db858065145192c97af90cb668ad72a12e9", dockerfile)
        self.assertIn("https://github.com/Maratyszcza/FXdiv.git", dockerfile)
        self.assertIn("63058eff77e11aa15bf531df5dd34395ec3017c8", dockerfile)
        self.assertIn("https://github.com/google/pthreadpool.git", dockerfile)
        self.assertIn("15a6644ba1c45f1acc16ac1e883efc3e56c6bed2", dockerfile)
        self.assertNotIn("attacker_controlled", dockerfile)

    def test_prefers_first_party_harness_over_vendored_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            vendored = source / "third_party" / "library"
            first_party = source / "tests" / "fuzz"
            vendored.mkdir(parents=True)
            first_party.mkdir(parents=True)
            for path in (vendored / "simple_fuzz.c", first_party / "fuzz.c"):
                path.write_text(
                    "int LLVMFuzzerTestOneInput(const unsigned char *data, "
                    "unsigned long size) { return 0; }\n"
                )

            selected = _find_existing_harness(source)

        self.assertEqual(selected, first_party / "fuzz.c")

    def test_public_library_sources_are_not_recompiled_as_harness_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "re2" / "fuzzing" / "fuzzer.cc"
            header = root / "re2" / "re2.h"
            source = root / "re2" / "re2.cc"
            harness.parent.mkdir(parents=True)
            harness.write_text('#include "re2/re2.h"\n')
            header.write_text("#pragma once\n")
            source.write_text('#include "re2/re2.h"\n')

            support_sources, include_dirs = _candidate_support_dependencies(
                root, {"file": "re2/fuzzing/fuzzer.cc"}
            )

        self.assertEqual(support_sources, [])
        self.assertEqual(include_dirs, [])

    def test_source_dependency_is_built_with_the_active_sanitizer_flags(self):
        script = _build_script("cmake", source_dependencies=["absl"])

        self.assertIn('cmake -S "/opt/fuzz-dependencies/absl"', script)
        self.assertIn('-DCMAKE_CXX_FLAGS="$CXXFLAGS"', script)
        self.assertIn('-DCMAKE_INSTALL_PREFIX="$WORK/dependencies"', script)
        self.assertIn('export CMAKE_PREFIX_PATH="$WORK/dependencies"', script)

    def test_source_directory_dependencies_are_injected_without_rebuilding(self):
        script = _build_script(
            "cmake", source_dependencies=["cpuinfo", "fxdiv", "pthreadpool"]
        )

        self.assertIn("-DCPUINFO_SOURCE_DIR=/opt/fuzz-dependencies/cpuinfo", script)
        self.assertIn(
            "-DPTHREADPOOL_SOURCE_DIR=/opt/fuzz-dependencies/pthreadpool", script
        )
        self.assertIn("-DFXDIV_SOURCE_DIR=/opt/fuzz-dependencies/fxdiv", script)
        self.assertNotIn('cmake -S "/opt/fuzz-dependencies/cpuinfo"', script)
        self.assertNotIn('cmake -S "/opt/fuzz-dependencies/fxdiv"', script)
        self.assertNotIn('cmake -S "/opt/fuzz-dependencies/pthreadpool"', script)
        self.assertIn("ENABLE_KLEIDIAI", script)

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
                self.assertNotIn("-type f -regex '.*[.](h|hh|hpp|hxx)'", script)
                if expected == "cmake":
                    self.assertIn("cmake_shared_args=(-DBUILD_SHARED_LIBS=OFF)", script)
                    self.assertIn("cmake_build_type=RelWithDebInfo", script)
                    self.assertIn("BUILD_(TESTS?", script)
                    self.assertEqual(script.count("grep -rhoEi 'option[(]"), 2)
                    self.assertIn("[Oo][Pp][Tt][Ii][Oo][Nn]", script)
                    self.assertIn('-DCMAKE_BUILD_TYPE="$cmake_build_type"', script)
                    self.assertIn('ninja -C "$WORK/build" -t commands', script)
                self.assertIn('find "$WORK/dependencies"', script)
                self.assertIn(
                    '-c "$SRC/generic_harness.cc" -o "$WORK/generic_harness.o"',
                    script,
                )
                self.assertIn('"$WORK/generic_harness.o"', script)
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
            self.assertNotIn(
                '"-I$SRC/project/"', (project / "build.sh").read_text()
            )
            self.assertEqual(
                (project / "generic_harness.cc").stat().st_mode & 0o777, 0o644
            )
            for name in ("Dockerfile", "build.sh", "project.yaml", "generic_harness.cc"):
                self.assertTrue((project / name).is_file())

    def test_existing_nested_harness_adds_its_header_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            project = root / "oss-fuzz-project"
            harness_dir = source / "tests" / "fuzz"
            external_dir = source / "contrib" / "external"
            public_include = source / "include" / "library"
            (root / "artifacts").mkdir()
            harness_dir.mkdir(parents=True)
            external_dir.mkdir(parents=True)
            public_include.mkdir(parents=True)
            (source / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.16)"
            )
            (harness_dir / "fuzz_helper.h").write_text("#pragma once\n")
            (harness_dir / "fuzz_helper.c").write_text(
                '#include "fuzz_helper.h"\n#include "external_helper.h"\n'
            )
            (external_dir / "external_helper.h").write_text("#pragma once\n")
            (external_dir / "external_helper.c").write_text(
                '#include "external_helper.h"\n#include "header_only.h"\n'
            )
            (external_dir / "header_only.h").write_text("#pragma once\n")
            (public_include / "api.h").write_text("#pragma once\n")
            (harness_dir / "block_fuzz.c").write_text(
                '#include "fuzz_helper.h"\n#include "library/api.h"\n'
                '#include <stddef.h>\n'
                'int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) '
                '{ return data != 0 && size > 0; }\n'
            )
            (harness_dir / "run_block_fuzz.c").write_text(
                '#include <stddef.h>\n'
                'int LLVMFuzzerTestOneInput(const unsigned char*, size_t);\n'
                'int main(void) { return 0; }\n'
            )

            result = create_generic_project(
                job_dir=root, source=source, project_dir=project,
                project_name="fts-test", pipeline={},
            )

            self.assertEqual(result["candidate"]["file"], "tests/fuzz/block_fuzz.c")
            self.assertEqual(result["harness_language"], "c")
            self.assertEqual(
                result["support_sources"],
                ["contrib/external/external_helper.c", "tests/fuzz/fuzz_helper.c"],
            )
            self.assertEqual(
                result["support_include_dirs"],
                ["contrib/external", "include", "tests/fuzz"],
            )
            self.assertIn(
                '"-I$SRC/project/tests/fuzz"',
                (project / "build.sh").read_text(),
            )
            self.assertIn(
                '"$SRC/project/tests/fuzz/fuzz_helper.c"',
                (project / "build.sh").read_text(),
            )
            self.assertIn(
                '"-I$SRC/project/contrib/external"',
                (project / "build.sh").read_text(),
            )
            self.assertIn(
                '"-I$SRC/project/include"',
                (project / "build.sh").read_text(),
            )
            self.assertNotIn(
                '"-I$SRC/project/include/library"',
                (project / "build.sh").read_text(),
            )
            self.assertIn(
                '"$SRC/project/contrib/external/external_helper.c"',
                (project / "build.sh").read_text(),
            )
            self.assertIn(
                '"$CC" $CFLAGS -x c', (project / "build.sh").read_text()
            )

            record_path = root / "artifacts" / "generic-integration.json"
            record_path.write_text(__import__("json").dumps(result))
            item = repair_generic_harness(
                job_dir=root, source=source, project_dir=project,
                pipeline={}, build_error="missing fuzz_helper.h", attempt=1,
            )
            self.assertEqual(
                item["repair_kind"], "deterministic_harness_include_path"
            )
            self.assertIn(
                '"-I$SRC/project/tests/fuzz"',
                (project / "build.sh").read_text(),
            )

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
