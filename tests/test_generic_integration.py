import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.harness_generation import validate_generated_harness
from fuzz_target_scout.pipeline import PipelineError
from fuzz_target_scout.generic_integration import (
    _dockerfile,
    _build_script,
    _candidate_support_dependencies,
    _detect_source_dependencies,
    _detect_system_dependencies,
    _infer_system_dependencies_from_build_error,
    _find_existing_harness,
    _generation_context,
    _has_root_cmake_interface_library,
    _select_public_candidate,
    create_generic_project,
    detect_build_system,
    repair_generic_harness,
)


class GenericIntegrationTests(unittest.TestCase):
    def test_multiline_stream_reader_factory_beats_teardown_and_stream_write(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "include" / "dna").mkdir(parents=True)
            (source / "include" / "trio").mkdir(parents=True)
            (source / "src" / "dna").mkdir(parents=True)
            (source / "src" / "trio" / "streams").mkdir(parents=True)
            (source / "include" / "dna" / "BinaryStreamReader.h").write_text(
                "class DNAAPI BinaryStreamReader : public StreamReader {\n"
                "public:\n"
                "  DNAAPI_MEMBER static BinaryStreamReader* create(BoundedIOStream* stream,\n"
                "                                    const Configuration& config = {},\n"
                "                                    MemoryResource* memRes = nullptr);\n"
                "  static void destroy(BinaryStreamReader* instance);\n"
                "  void read() override;\n"
                "};\n"
            )
            (source / "src" / "dna" / "WriterImpl.h").write_text(
                "struct WriterImpl {\n"
                "  void setDBComplexity(const char* name) override;\n"
                "};\n"
            )
            (source / "src" / "trio" / "streams" / "FileStreamImpl.h").write_text(
                "struct FileStreamImpl {\n"
                "  std::size_t read(char* destination, std::size_t size) override;\n"
                "};\n"
            )
            (source / "include" / "trio" / "MemoryStream.h").write_text(
                "class MemoryStream {\npublic:\n"
                "  void write(const char* bytes, size_t length);\n"
                "};\n"
            )

            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["file"], "include/dna/BinaryStreamReader.h")
        self.assertEqual(candidate["local_symbol_line"], 3)
        self.assertIn("DNAAPI_MEMBER static BinaryStreamReader* create(BoundedIOStream* stream,", candidate["signature"])
        self.assertIn("const Configuration& config = {}", candidate["signature"])
        self.assertNotIn("destroy", candidate["signature"])

    def test_mutable_read_destination_is_not_a_fuzz_input_api(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "api.h").write_text(
                "std::size_t read(char* destination, std::size_t size);\n"
                "std::size_t readBytes(uint8_t* dst, std::size_t size);\n"
            )
            with self.assertRaisesRegex(PipelineError, "no existing harness"):
                _select_public_candidate(source)

    def test_stream_factory_context_exposes_bounded_memory_adapter_and_read_api(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "include" / "dna").mkdir(parents=True)
            (source / "include" / "trio").mkdir(parents=True)
            (source / "include" / "dna" / "BinaryStreamReader.h").write_text(
                "class BinaryStreamReader : public StreamReader {\n"
                "public:\n"
                "  static BinaryStreamReader* create(\n"
                "      BoundedIOStream* source);\n"
                "};\n"
            )
            (source / "include" / "dna" / "StreamReader.h").write_text(
                "class StreamReader {\npublic:\n"
                "  virtual void read() = 0;\n"
                "};\n"
            )
            (source / "include" / "trio" / "MemoryStream.h").write_text(
                "class MemoryStream : public BoundedIOStream {\npublic:\n"
                "  void write(const char* data, size_t size);\n"
                "  void seek(size_t offset);\n"
                "};\n"
            )
            candidate = _select_public_candidate(source)
            context = _generation_context(source, candidate)

        self.assertIn("create( BoundedIOStream* source)", candidate["signature"])
        self.assertIn("Related public header: include/trio/MemoryStream.h", context)
        self.assertIn("write(const char* data, size_t size)", context)
        self.assertIn("seek(size_t offset)", context)
        self.assertIn("Related public header: include/dna/StreamReader.h", context)
        self.assertIn("void read()", context)
        self.assertLessEqual(len(context), 18000)

    def test_direct_byte_parser_beats_stream_factory(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "reader.h").write_text(
                "struct Reader {\n"
                "  static Reader* create(InputStream* source);\n"
                "  static void destroy(Reader* instance);\n"
                "};\n"
                "int decode(const uint8_t* data, size_t length);\n"
            )
            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["signature"],
                         "int decode(const uint8_t* data, size_t length);")

    def test_public_include_parser_beats_equal_internal_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "include").mkdir()
            (source / "src").mkdir()
            (source / "include" / "reader.h").write_text(
                "int parse(InputStream* input);\n"
            )
            (source / "src" / "reader_impl.h").write_text(
                "int parse(InputStream* input);\n"
            )
            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["file"], "include/reader.h")

    def test_direct_byte_api_does_not_add_unrelated_stream_context(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "parse.h").write_text(
                "int parse(const uint8_t* data, size_t size);\n"
            )
            (source / "MemoryStream.h").write_text(
                "class MemoryStream {\npublic:\nvoid write(const char* data);\n};\n"
            )
            candidate = _select_public_candidate(source)
            context = _generation_context(source, candidate)

        self.assertIn("int parse(const uint8_t* data", context)
        self.assertNotIn("Related public header", context)

    def test_lifetime_only_header_has_no_fuzzable_function_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "api.h").write_text(
                "void destroy(void* instance);\n"
                "void Buffer_free(void* instance);\n"
                "void releaseBuffer(void* instance);\n"
            )
            with self.assertRaisesRegex(PipelineError, "no existing harness"):
                _select_public_candidate(source)

    def test_state_only_methods_do_not_trigger_harness_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "api.h").write_text(
                "bool isReady();\n"
                "void refresh();\n"
            )
            with self.assertRaisesRegex(PipelineError, "no existing harness"):
                _select_public_candidate(source)

    def test_multiline_private_stream_parser_does_not_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "api.h").write_text(
                "class Reader {\n"
                "  int parse_private(\n"
                "      InputStream* stream);\n"
                "public:\n"
                "  int parse_public(\n"
                "      InputStream* stream);\n"
                "};\n"
            )
            candidate = _select_public_candidate(source)

        self.assertIn("parse_public", candidate["signature"])
        self.assertNotIn("parse_private", candidate["signature"])

    def test_public_candidate_prefers_data_parser_over_zero_input_method(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "include").mkdir()
            parser_dir = source / "src" / "config"
            parser_dir.mkdir(parents=True)
            (source / "include" / "context.h").write_text(
                "class Context {\n"
                "public:\n"
                "  bool refresh();\n"
                "};\n"
            )
            (parser_dir / "json_parser.h").write_text(
                "class JsonParser {\n"
                "public:\n"
                "  Result parse(const std::string& input);\n"
                "};\n"
            )

            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["file"], "src/config/json_parser.h")
        self.assertEqual(candidate["signature"], "Result parse(const std::string& input);")

    def test_public_candidate_prefers_byte_argument_over_zero_input_method(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "api.h").write_text(
                "bool refresh();\n"
                "int consume(const uint8_t* data, size_t size);\n"
            )

            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["signature"], "int consume(const uint8_t* data, size_t size);")

    def test_public_candidate_prefers_exported_header_over_benchmark_expression(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "bench").mkdir()
            (source / "include").mkdir()
            (source / "bench" / "pack.h").write_text(
                "num_blocks * sizeof(uint16_t) + sizeof(float));\n"
            )
            (source / "include" / "api.h").write_text(
                "int parse_bytes(const unsigned char* data, unsigned long size);\n"
            )

            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["file"], "include/api.h")
        self.assertIn("parse_bytes", candidate["signature"])

    def test_private_and_protected_class_methods_are_not_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            header = source / "api.h"
            header.write_text(
                "class Cache {\n"
                "  void hidden_by_default();\n"
                "public:\n"
                "protected:\n"
                "  void hidden_protected();\n"
                "private:\n"
                "  void recomputeReadCache();\n"
                "public:\n"
                "  int parse_public(const unsigned char* data);\n"
                "};\n"
            )
            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["signature"], "int parse_public(const unsigned char* data);")
        self.assertEqual(candidate["local_symbol_line"], 9)

    def test_struct_default_public_methods_remain_eligible(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "api.h").write_text(
                "struct Parser {\n"
                "  int parse_bytes(const unsigned char* data);\n"
                "};\n"
            )
            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["signature"], "int parse_bytes(const unsigned char* data);")

    def test_nested_private_method_does_not_hide_later_free_function(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "api.h").write_text(
                "class Outer {\n"
                "private:\n"
                "  struct Hidden {\n"
                "    int parse_hidden(const unsigned char* data);\n"
                "  };\n"
                "  /* } */ void recomputeReadCache();\n"
                "};\n"
                "int parse_free(const unsigned char* data);\n"
            )
            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["signature"], "int parse_free(const unsigned char* data);")
        self.assertEqual(candidate["local_symbol_line"], 8)

    def test_benchmark_only_header_is_not_used_as_a_public_api(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "benchmarks").mkdir()
            (source / "benchmarks" / "helper.h").write_text(
                "int benchmark_helper(const unsigned char* data);\n"
            )
            with self.assertRaisesRegex(PipelineError, "no existing harness"):
                _select_public_candidate(source)

    def test_macro_body_and_expression_are_not_selected_as_prototypes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            header = source / "EnumFlagsO.h"
            header.write_text("\n".join([
                "#define MY_ENUMFLAGS_OSTREAM_OVERLOAD(NAME) " + chr(92),
                "  os << toPretty(value); " + chr(92),
                "  os << value",
                "sink << parse_fake(data);",
                "return parse_fake(data);",
                "std::vector<std::vector<int>> parse_bytes(const char* data, size_t size);",
            ]) + "\n")

            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["signature"],
                         "std::vector<std::vector<int>> parse_bytes(const char* data, size_t size);")
        self.assertEqual(candidate["local_symbol_line"], 6)
        self.assertNotEqual(candidate.get("candidate_kind"), "macro")

    def test_public_macro_definition_is_fallback_when_no_function_is_declared(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            header = source / "EnumFlagsO.h"
            header.write_text("\n".join([
                "#define MY_ENUMFLAGS_OSTREAM_OVERLOAD(NAME) " + chr(92),
                "  os << toPretty(value); " + chr(92),
                "  os << value",
                "#define MY_ENUMFLAGS_DEF_O(EnumName, UINT_TYPE, ...) " + chr(92),
                "  enum class EnumName : UINT_TYPE { __VA_ARGS__ };",
                "#define MY_ENUMFLAGS_O(EnumName, UINT_TYPE, ...) " + chr(92),
                "  MY_ENUMFLAGS_DEF_O(EnumName, UINT_TYPE, __VA_ARGS__)",
                "MY_ENUMFLAGS_O(FuzzFlags, uint64_t, Alpha, Beta);",
            ]) + "\n")

            candidate = _select_public_candidate(source)
            next_candidate = _select_public_candidate(source, {candidate["id"]})

        self.assertEqual(candidate["signature"],
                         "MY_ENUMFLAGS_O(EnumName, UINT_TYPE, ...)")
        self.assertEqual(candidate["candidate_kind"], "macro")
        self.assertEqual(candidate["local_symbol_line"], 6)
        validation = validate_generated_harness(
            "MY_ENUMFLAGS_O(FuzzFlags, uint64_t, Alpha, Beta); "
            "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t* data, "
            "size_t size) { return size > 0 && data[0] ? 1 : 0; }",
            candidate,
        )
        self.assertEqual(validation["target_symbol"], "MY_ENUMFLAGS_O")
        self.assertNotEqual(next_candidate["id"], candidate["id"])
        self.assertNotIn("os <<", next_candidate["signature"])

    def test_internal_header_declaration_does_not_preempt_public_macro(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "impl").mkdir()
            (source / "impl" / "helper.h").write_text(
                "int parse_internal(const unsigned char* data);"
            )
            (source / "Enum.h").write_text(
                "#define MY_ENUM(NAME, ...) " + chr(92) + chr(10)
                + "  enum class NAME { __VA_ARGS__ };" + chr(10)
            )

            candidate = _select_public_candidate(source)

        self.assertEqual(candidate["signature"], "MY_ENUM(NAME, ...)")
        self.assertEqual(candidate["candidate_kind"], "macro")

    def test_macro_use_and_continuation_without_definition_are_not_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "api.h").write_text("\n".join([
                "os << toPretty(value); " + chr(92),
                "return parse_fake(data);",
                "MY_ENUMFLAGS_O(FuzzFlags, uint64_t, Alpha, Beta);",
            ]) + "\n")
            with self.assertRaisesRegex(PipelineError, "no existing harness"):
                _select_public_candidate(source)

    def test_generation_records_selected_macro_before_adapter_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            job = Path(directory)
            source = job / "source"
            source.mkdir()
            (source / "CMakeLists.txt").write_text("project(enum)")
            (source / "EnumFlagsO.h").write_text(
                "#define MY_ENUMFLAGS_O(EnumName, UINT_TYPE, ...) " + chr(92) + "\n"
                "  enum class EnumName : UINT_TYPE { __VA_ARGS__ };\n"
            )
            with patch(
                "fuzz_target_scout.generic_integration.invoke_oss_fuzz_gen_adapter",
                side_effect=PipelineError("adapter failed"),
            ):
                with self.assertRaisesRegex(PipelineError, "adapter failed"):
                    create_generic_project(
                        job_dir=job, source=source, project_dir=job / "integration",
                        project_name="enum", pipeline={},
                    )
            selection = json.loads(
                (job / "artifacts" / "generic-integration-selection.json").read_text()
            )

        self.assertEqual(selection["schema_version"], 1)
        self.assertEqual(selection["candidate"]["candidate_kind"], "macro")
        self.assertEqual(selection["candidate"]["file"], "EnumFlagsO.h")
        self.assertTrue(selection["candidate"]["id"])

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
        self.assertIn("git flex bison", dockerfile)
        self.assertIn("ARG FUZZ_UID=1000", dockerfile)
        self.assertIn("ARG FUZZ_GID=1000", dockerfile)
        self.assertIn('getent passwd "$FUZZ_UID"', dockerfile)
        self.assertIn('useradd --uid "$FUZZ_UID"', dockerfile)
        self.assertIn("COPY --chmod=0644 generic_harness.cc", dockerfile)
        self.assertNotIn("gcr.io/oss-fuzz-base", dockerfile)

    def test_native_meson_builder_has_source_generation_tools(self):
        dockerfile = _dockerfile("meson", "ubuntu:24.04")
        self.assertIn("meson ninja-build pkg-config python3 python3-yaml ragel", dockerfile)
        self.assertIn("git flex bison", dockerfile)

    def test_meson_default_required_jsoncpp_is_installed_and_linked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            project = root / "project"
            (root / "artifacts").mkdir()
            source.mkdir()
            (source / "meson.build").write_text(
                "project('parser', 'cpp')\n"
                "dependency('jsoncpp')\n"
                "dependency('libsystemd', required: false)\n"
            )
            (source / "fuzz.cc").write_text(
                '#include <cstddef>\n#include <cstdint>\n'
                'extern "C" int LLVMFuzzerTestOneInput('
                'const uint8_t*, size_t) { return 0; }\n'
            )
            record = create_generic_project(
                job_dir=root, source=source, project_dir=project,
                project_name="parser", pipeline={}, native=True,
            )
            dockerfile = (project / "Dockerfile").read_text()
            build = (project / "build.sh").read_text()
        self.assertEqual(record["system_dependencies"], ["libjsoncpp-dev"])
        self.assertIn("libjsoncpp-dev", dockerfile)
        self.assertIn("pkg-config --libs jsoncpp", build)
        self.assertIn('"${meson_external_libs[@]}"', build)

    def test_meson_build_compiles_only_static_libraries(self):
        build = _build_script("meson", "", [], "c++", [], [])
        self.assertIn("meson-info/intro-targets.json", build)
        self.assertIn("target.get('type') != 'static library'", build)
        self.assertIn('ninja -C "$WORK/build" "${archive_targets[@]}"', build)
        self.assertNotIn('meson compile -C "$WORK/build"', build)

    def test_meson_ninja_include_paths_resolve_from_build_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            build = work / "build"
            source_dir = root / "source"
            binary_dir = root / "bin"
            build.mkdir(parents=True)
            (source_dir / "project").mkdir(parents=True)
            binary_dir.mkdir()
            (build / "build.ninja").write_text("")
            ninja = binary_dir / "ninja"
            ninja.write_text(
                "#!/bin/sh" + chr(10)
                + "echo 'cc -Igenerated -I ../project/from-build "
                  "-isystemvendor -isystem /usr/include "
                  "-iquotequote -iquote ../project/quoted -I /opt/external'"
                + chr(10)
            )
            ninja.chmod(0o755)

            script = _build_script("meson")
            start = script.index('include_flags=')
            end = script.index('if (( ${#archives[@]} == 0 && ${#shared_libraries[@]} == 0 &&', start)
            snippet = script[start:end] + (
                'for flag in "${include_flags[@]}"; do echo "$flag"; done'
            )
            result = subprocess.run(
                ["bash", "-c", "set -euo pipefail" + chr(10) + snippet],
                env={
                    **os.environ,
                    "SRC": str(source_dir),
                    "WORK": str(work),
                    "PATH": str(binary_dir) + os.pathsep + os.environ["PATH"],
                },
                check=True,
                capture_output=True,
                text=True,
            )

            flags = result.stdout.splitlines()
            self.assertIn(f"-I{source_dir / 'project'}", flags)
            self.assertIn(f"-I{build}", flags)
            self.assertIn(f"-I{build / 'generated'}", flags)
            self.assertIn(f"-I{build / '../project/from-build'}", flags)
            self.assertIn(f"-isystem{build / 'vendor'}", flags)
            self.assertIn("-isystem/usr/include", flags)
            self.assertIn(f"-iquote{build / 'quote'}", flags)
            self.assertIn(f"-iquote{build / '../project/quoted'}", flags)
            self.assertIn("-I/opt/external", flags)

    def test_cmake_dependencies_are_inferred_from_a_reviewed_allow_list(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "CMakeLists.txt").write_text(
                "find_package(absl REQUIRED)\n"
                "find_package(Boost REQUIRED)\n"
                "find_package(GTest REQUIRED)\n"
                "find_package(OpenSSL REQUIRED)\n"
                "find_package(UUID REQUIRED)\n"
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

        self.assertEqual(dependencies, ["libboost-dev", "libgflags-dev", "libgtest-dev", "libssl-dev", "uuid-dev"])
        self.assertEqual(
            source_dependencies, ["absl", "cpuinfo", "fxdiv", "pthreadpool"]
        )
        self.assertIn("libboost-dev libgflags-dev libgtest-dev libssl-dev uuid-dev git", dockerfile)
        self.assertIn("https://github.com/abseil/abseil-cpp.git", dockerfile)
        self.assertIn("d38452e1ee03523a208362186fd42248ff2609f6", dockerfile)
        self.assertIn("https://github.com/pytorch/cpuinfo.git", dockerfile)
        self.assertIn("8ce83db858065145192c97af90cb668ad72a12e9", dockerfile)
        self.assertIn("https://github.com/Maratyszcza/FXdiv.git", dockerfile)
        self.assertIn("63058eff77e11aa15bf531df5dd34395ec3017c8", dockerfile)
        self.assertIn("https://github.com/google/pthreadpool.git", dockerfile)
        self.assertIn("15a6644ba1c45f1acc16ac1e883efc3e56c6bed2", dockerfile)
        self.assertNotIn("attacker_controlled", dockerfile)

    def test_nested_cmake_cli11_dependency_is_bounded_and_symlink_safe(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            source = Path(directory)
            (source / "CMakeLists.txt").write_text(
                "add_subdirectory(examples)\n", encoding="utf-8"
            )
            examples = source / "examples"
            examples.mkdir()
            (examples / "CMakeLists.txt").write_text(
                "find_package(CLI11 CONFIG REQUIRED)\n"
                "find_package(unreviewed REQUIRED)\n",
                encoding="utf-8",
            )
            external = Path(outside) / "CMakeLists.txt"
            external.write_text("find_package(Protobuf REQUIRED)\n", encoding="utf-8")
            (source / "linked").symlink_to(Path(outside), target_is_directory=True)
            cmake = source / "cmake"
            cmake.mkdir()
            (cmake / "linked-file.cmake").symlink_to(external)
            large = source / "large"
            large.mkdir()
            (large / "CMakeLists.txt").write_text(
                " " * 250_001 + "find_package(gflags REQUIRED)\n",
                encoding="utf-8",
            )

            dependencies = _detect_system_dependencies(source, "cmake")
            dockerfile = _dockerfile("cmake", "ubuntu:24.04", dependencies)

        self.assertEqual(dependencies, ["libcli11-dev"])
        self.assertIn("libcli11-dev", dockerfile)
        self.assertNotIn("unreviewed", dockerfile)
        self.assertNotIn("libprotobuf-dev", dockerfile)
        self.assertNotIn("libgflags-dev", dockerfile)

    def test_meson_required_dependencies_use_reviewed_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            nested = source / "meson" / "lua"
            nested.mkdir(parents=True)
            (source / "meson.build").write_text(
                "dependency('libssl', required: true)\n"
                "dependency('attacker-controlled', required: true)\n"
            )
            (nested / "meson.build").write_text(
                "dep_lua = dependency('lua5.4', required: false)\n"
                "error('No Lua implementation was found')\n"
            )

            dependencies = _detect_system_dependencies(source, "meson")
            dockerfile = _dockerfile("meson", "ubuntu:24.04", dependencies)

        self.assertEqual(dependencies, ["liblua5.4-dev", "libssl-dev"])
        self.assertIn("liblua5.4-dev libssl-dev", dockerfile)
        self.assertNotIn("attacker-controlled", dockerfile)

    def test_missing_reviewed_build_tools_are_inferred_from_fatal_errors(self):
        dependencies = _infer_system_dependencies_from_build_error(
            "Program curl found: NO\n"
            "meson.build:347:10: ERROR: Program 'ragel' not found or not executable\n"
            "ModuleNotFoundError: No module named 'yaml'\n"
            "meson.build:400:10: ERROR: Program 'unapproved-tool' not found"
        )
        self.assertEqual(dependencies, {"ragel", "python3-yaml"})
        dockerfile = _dockerfile(
            "meson", "ubuntu:24.04", sorted(dependencies)
        )
        self.assertIn("python3-yaml ragel", dockerfile)
        self.assertNotIn("unapproved-tool", dockerfile)

    def test_exact_cmake_uuid_failure_repairs_builder_without_ai(self):
        error = (
            "CMake Error at /usr/share/cmake-3.28/Modules/FindPackageHandleStandardArgs.cmake:230 (message):\n"
            "  Could NOT find UUID (missing: UUID_LIBRARY UUID_INCLUDE_DIR)\n"
        )
        self.assertEqual(
            _infer_system_dependencies_from_build_error(error), {"uuid-dev"}
        )
        self.assertEqual(
            _infer_system_dependencies_from_build_error(
                "Could NOT find Other (missing: UUID_LIBRARY UUID_INCLUDE_DIR)"
            ),
            set(),
        )

    def test_exact_cmake_gtest_failure_repairs_builder_without_touching_harness(self):
        error = (
            "CMake Error at /usr/share/cmake/Modules/FindPackageHandleStandardArgs.cmake:230 (message):\n"
            "  Could NOT find GTest (missing: GTEST_LIBRARY GTEST_INCLUDE_DIR GTEST_MAIN_LIBRARY)\n"
        )
        self.assertEqual(
            _infer_system_dependencies_from_build_error(error),
            {"libgtest-dev"},
        )
        self.assertEqual(
            _infer_system_dependencies_from_build_error(
                "Could NOT find GTest (missing: GTEST_INCLUDE_DIR)"
            ),
            set(),
        )
        self.assertEqual(
            _infer_system_dependencies_from_build_error(
                "Could NOT find Other (missing: GTEST_LIBRARY GTEST_INCLUDE_DIR GTEST_MAIN_LIBRARY)"
            ),
            set(),
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            project = root / "project"
            artifacts = root / "artifacts"
            for path in (source, project, artifacts):
                path.mkdir()
            harness = (
                'extern "C" int LLVMFuzzerTestOneInput('
                'const unsigned char*, unsigned long) { return 0; }\n'
            )
            (project / "generic_harness.cc").write_text(harness)
            (project / "build.sh").write_text("#!/bin/sh\n")
            (project / "Dockerfile").write_text("FROM ubuntu:24.04\n")
            record = {
                "project": "fts-test",
                "build_system": "cmake",
                "execution_mode": "native_container",
                "base_image": "ubuntu:24.04",
                "candidate": {"file": "src/api.h"},
                "harness_origin": "codex_oss_fuzz_gen_adapter",
                "system_dependencies": [],
                "source_dependencies": [],
                "repair_attempts": [],
            }
            (artifacts / "generic-integration.json").write_text(
                json.dumps(record)
            )
            with patch(
                "fuzz_target_scout.generic_integration.invoke_oss_fuzz_gen_adapter"
            ) as regenerate:
                repair = repair_generic_harness(
                    job_dir=root, source=source, project_dir=project,
                    pipeline={}, build_error=error, attempt=1,
                )
                regenerate.assert_not_called()
            saved = json.loads(
                (artifacts / "generic-integration.json").read_text()
            )
            self.assertEqual(
                (project / "generic_harness.cc").read_text(), harness
            )
            self.assertEqual((project / "build.sh").read_text(), "#!/bin/sh\n")
            self.assertIn("libgtest-dev", (project / "Dockerfile").read_text())
            self.assertEqual(repair["repair_kind"], "deterministic_system_dependency")
            self.assertEqual(repair["added_system_dependencies"], ["libgtest-dev"])
            self.assertTrue(repair["requires_clean_build"])
            self.assertEqual(saved["system_dependencies"], ["libgtest-dev"])

    def test_build_feedback_adds_only_reviewed_system_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            project = root / "project"
            artifacts = root / "artifacts"
            for path in (source, project, artifacts):
                path.mkdir(parents=True)
            (project / "Dockerfile").write_text("FROM ubuntu:24.04\n")
            (project / "generic_harness.cc").write_text(
                "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char*, "
                "unsigned long) { return 0; }\n"
            )
            record = {
                "project": "fts-test",
                "build_system": "meson",
                "execution_mode": "native_container",
                "base_image": "ubuntu:24.04",
                "candidate": {"file": "fuzz.cc"},
                "harness_origin": "existing:fuzz.cc",
                "system_dependencies": [],
                "source_dependencies": [],
                "repair_attempts": [],
            }
            (artifacts / "generic-integration.json").write_text(
                __import__("json").dumps(record)
            )

            result = repair_generic_harness(
                job_dir=root,
                source=source,
                project_dir=project,
                pipeline={},
                build_error=(
                    "meson/lua/meson.build:43:2: ERROR: No Lua implementation was found\n"
                    'meson/libcrypto/meson.build:22:18: ERROR: Dependency "libcrypto" not found\n'
                    'meson/boost/meson.build:1:12: ERROR: Dependency "boost" not found'
                ),
                attempt=1,
            )

            saved = __import__("json").loads(
                (artifacts / "generic-integration.json").read_text()
            )
            dockerfile = (project / "Dockerfile").read_text()
        self.assertEqual(result["repair_kind"], "deterministic_system_dependency")
        self.assertEqual(
            result["added_system_dependencies"],
            [
                "libboost-context-dev",
                "libboost-dev",
                "libboost-program-options-dev",
                "libboost-serialization-dev",
                "liblua5.4-dev",
                "libssl-dev",
            ],
        )
        self.assertTrue(result["requires_clean_build"])
        self.assertEqual(
            saved["system_dependencies"],
            [
                "libboost-context-dev",
                "libboost-dev",
                "libboost-program-options-dev",
                "libboost-serialization-dev",
                "liblua5.4-dev",
                "libssl-dev",
            ],
        )
        self.assertIn("libboost-context-dev", dockerfile)
        self.assertIn("libboost-program-options-dev", dockerfile)
        self.assertIn("libboost-serialization-dev", dockerfile)
        self.assertIn("liblua5.4-dev", dockerfile)
        self.assertIn("libssl-dev", dockerfile)

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
        self.assertIn('if [[ "$reuse_build" != "1" ]]', script)

    def test_harness_retry_can_reuse_the_completed_library_build(self):
        script = _build_script("cmake")

        self.assertIn('reuse_build="${FUZZ_REUSE_BUILD:-0}"', script)
        self.assertIn('rm -rf "$WORK/build"', script)
        self.assertLess(
            script.index('if [[ "$reuse_build" != "1" ]]'),
            script.index('rm -rf "$WORK/build"'),
        )

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
        self.assertIn("ALL_MICROKERNELS", script)

    def test_cmake_fuzz_build_disables_discovered_test_options(self):
        script = _build_script("cmake")
        start = script.index("cmake_shared_args=(-DBUILD_SHARED_LIBS=OFF)")
        end = script.index("cmake_build_type=RelWithDebInfo", start)
        option_discovery = script[start:end]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "CMakeLists.txt").write_text(
                "option(BUILD_TESTING \"Run tests\" ON)\n"
                "option(BENCHMARK_ENABLE_TESTING \"Run benchmark tests\" ON)\n"
                "option(BENCHMARK_ENABLE_INSTALL \"Install\" ON)\n"
            )
            result = subprocess.run(
                ["bash", "-c", option_discovery + "printf '%s\\n' \"${cmake_shared_args[@]}\"\n"],
                cwd=source, capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        args = set(result.stdout.splitlines())
        self.assertIn("-DBUILD_TESTING=OFF", args)
        self.assertIn("-DBENCHMARK_ENABLE_TESTING=OFF", args)
        self.assertNotIn("-DBENCHMARK_ENABLE_INSTALL=OFF", args)

    def test_interface_library_must_be_declared_in_active_root_cmake(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            nested = source / "nested"
            nested.mkdir()
            (nested / "CMakeLists.txt").write_text(
                "add_library(Nested INTERFACE)\n"
            )
            root = source / "CMakeLists.txt"
            root.write_text("add_subdirectory(nested)\n")
            self.assertFalse(_has_root_cmake_interface_library(source))
            root.write_text(
                "# add_library(Commented INTERFACE)\n"
                "#[[\nadd_library(BlockComment INTERFACE)\n]]\n"
                "add_library(MyEnum STATIC enum.cc)\n"
            )
            self.assertFalse(_has_root_cmake_interface_library(source))
            root.write_text("add_library(MyEnum INTERFACE)\n")
            self.assertTrue(_has_root_cmake_interface_library(source))
            root.unlink()
            root.symlink_to(nested / "CMakeLists.txt")
            self.assertFalse(_has_root_cmake_interface_library(source))

    @unittest.skipUnless(
        os.name == "posix" and shutil.which("bash") and shutil.which("g++"),
        "requires Bash and a C++ compiler",
    )
    def test_header_only_cmake_links_without_archives_but_other_builds_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src"
            project = source / "project"
            work = root / "work"
            out = root / "out"
            tools = root / "tools"
            project.mkdir(parents=True)
            tools.mkdir()
            cmake_file = project / "CMakeLists.txt"
            cmake_file.write_text("add_library(MyEnum INTERFACE)\n")
            (project / "api.h").write_text(
                "inline int consume(const unsigned char *data, unsigned long size) "
                "{ return size && data[0] == 7 ? 0 : 1; }\n"
            )
            (source / "generic_harness.cc").write_text(
                '#include "api.h"\n'
                'extern "C" int LLVMFuzzerTestOneInput('
                'const unsigned char *data, unsigned long size) '
                '{ return consume(data, size); }\n'
                'int main() { unsigned char value = 7; '
                'return LLVMFuzzerTestOneInput(&value, 1); }\n'
            )
            fake_cmake = tools / "cmake"
            fake_cmake.write_text("#!/bin/sh\nexit 0\n")
            fake_cmake.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
                "SRC": str(source), "WORK": str(work), "OUT": str(out),
                "CC": "gcc", "CXX": "g++", "CFLAGS": "-O0",
                "CXXFLAGS": "-O0", "LIB_FUZZING_ENGINE": "",
            }
            script = source / "build.sh"
            script.write_text(_build_script(
                "cmake",
                allow_header_only_cmake=_has_root_cmake_interface_library(project),
            ))
            allowed = subprocess.run(
                ["bash", str(script)], cwd=project, env=environment,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(allowed.returncode, 0, allowed.stderr)
            fuzzer = out / "generic_fuzzer"
            self.assertTrue(fuzzer.is_file())
            self.assertEqual(subprocess.run([str(fuzzer)], timeout=5).returncode, 0)

            cmake_file.write_text("add_library(MyEnum STATIC enum.cc)\n")
            script.write_text(_build_script(
                "cmake",
                allow_header_only_cmake=_has_root_cmake_interface_library(project),
            ))
            refused = subprocess.run(
                ["bash", str(script)], cwd=project, env=environment,
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("found no linkable libraries", refused.stderr)
            self.assertIn(
                "1 == 1 ));", _build_script("meson", allow_header_only_cmake=True)
            )

    @unittest.skipUnless(
        os.name == "posix" and shutil.which("bash") and shutil.which("g++"),
        "requires Bash and a C++ compiler",
    )
    def test_cmake_shared_library_is_linked_and_available_at_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src"
            project = source / "project"
            work = root / "work"
            out = root / "out"
            tools = root / "tools"
            project.mkdir(parents=True)
            tools.mkdir()
            (project / "CMakeLists.txt").write_text(
                "add_library(Foo SHARED foo.cpp)\n"
            )
            (project / "foo.cpp").write_text(
                'extern "C" int foo() { return 7; }\n'
            )
            (project / "api.h").write_text('extern "C" int foo();\n')
            (source / "generic_harness.cc").write_text(
                '#include "api.h"\n'
                'extern "C" int LLVMFuzzerTestOneInput('
                'const unsigned char*, unsigned long) '
                '{ return foo() == 7 ? 0 : 1; }\n'
                'int main() { return LLVMFuzzerTestOneInput(nullptr, 0); }\n'
            )
            fake_cmake = tools / "cmake"
            fake_cmake.write_text(
                '#!/bin/sh\n'
                'if [ "$1" = "--build" ]; then\n'
                '  g++ -shared -fPIC "$PWD/foo.cpp" -o "$WORK/build/libfoo.so"\n'
                'fi\n'
            )
            fake_cmake.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
                "SRC": str(source), "WORK": str(work), "OUT": str(out),
                "CC": "gcc", "CXX": "g++", "CFLAGS": "-O0",
                "CXXFLAGS": "-O0", "LIB_FUZZING_ENGINE": "",
            }
            script = source / "build.sh"
            script.write_text(_build_script("cmake"))
            result = subprocess.run(
                ["bash", str(script)], cwd=project, env=environment,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((out / "libfoo.so").is_file())
            self.assertEqual(
                subprocess.run(
                    [str(out / "generic_fuzzer")],
                    capture_output=True, text=True, timeout=5,
                ).returncode,
                0,
            )

    def test_generic_project_preserves_interface_link_permission_on_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            project = root / "project"
            artifacts = root / "artifacts"
            source.mkdir()
            artifacts.mkdir()
            (source / "CMakeLists.txt").write_text(
                "add_library(MyEnum INTERFACE)\n"
            )
            (source / "fuzz.cc").write_text(
                '#include <cstddef>\n#include <cstdint>\n'
                'extern "C" int LLVMFuzzerTestOneInput('
                'const uint8_t*, size_t) { return 0; }\n'
            )
            record = create_generic_project(
                job_dir=root, source=source, project_dir=project,
                project_name="fts-test", pipeline={}, native=True,
            )
            self.assertTrue(record["allow_header_only_cmake"])
            self.assertIn("0 == 1 ));", (project / "build.sh").read_text())
            (artifacts / "generic-integration.json").write_text(json.dumps(record))
            repair_generic_harness(
                job_dir=root, source=source, project_dir=project,
                pipeline={}, build_error="header include error", attempt=1,
            )
            self.assertIn("0 == 1 ));", (project / "build.sh").read_text())
            saved = json.loads((artifacts / "generic-integration.json").read_text())
            self.assertTrue(saved["allow_header_only_cmake"])

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
