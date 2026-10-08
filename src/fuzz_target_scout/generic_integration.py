from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Callable

from .harness_generation import (
    extract_harness_code,
    generation_prompt,
    invoke_oss_fuzz_gen_adapter,
    source_context,
    validate_generated_harness,
)
from .pipeline import PipelineError, utc_now


BUILD_SYSTEM_MARKERS = (
    ("cmake", ("CMakeLists.txt",)),
    ("meson", ("meson.build",)),
    ("autotools", ("configure.ac", "configure.in", "Makefile.am")),
    ("cargo", ("Cargo.toml",)),
)
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx"}
HARNESS_SUPPORT_DIRECTORY_NAMES = {"test", "tests", "fuzz", "fuzzer", "fuzzing"}

# Only install packages from this reviewed allow-list.  Project-controlled CMake
# files may name arbitrary packages, so inferred values must never reach apt
# directly.
CMAKE_SYSTEM_DEPENDENCIES = {
    "boost": ("libboost-dev",),
    "bzip2": ("libbz2-dev",),
    "cli11": ("libcli11-dev",),
    "expat": ("libexpat1-dev",),
    "gflags": ("libgflags-dev",),
    "gtest": ("libgtest-dev",),
    "libxml2": ("libxml2-dev",),
    "openssl": ("libssl-dev",),
    "protobuf": ("libprotobuf-dev", "protobuf-compiler"),
    "zlib": ("zlib1g-dev",),
}
MESON_SYSTEM_DEPENDENCIES = {
    "boost": (
        "libboost-context-dev",
        "libboost-dev",
        "libboost-program-options-dev",
        "libboost-serialization-dev",
    ),
    "bzip2": ("libbz2-dev",),
    "libcurl": ("libcurl4-openssl-dev",),
    "libcrypto": ("libssl-dev",),
    "jsoncpp": ("libjsoncpp-dev",),
    "libpcre2-8": ("libpcre2-dev",),
    "libsodium": ("libsodium-dev",),
    "libssl": ("libssl-dev",),
    "lua": ("liblua5.4-dev",),
    "lua5.4": ("liblua5.4-dev",),
    "openssl": ("libssl-dev",),
    "protobuf": ("libprotobuf-dev", "protobuf-compiler"),
    "sqlite3": ("libsqlite3-dev",),
    "yaml-0.1": ("libyaml-dev",),
    "zlib": ("zlib1g-dev",),
}
REVIEWED_BUILD_TOOL_PACKAGES = frozenset(
    {"bison", "flex", "gperf", "ragel", "socat", "python3-yaml"}
)
REVIEWED_SYSTEM_PACKAGES = frozenset(
    package
    for mapping in (CMAKE_SYSTEM_DEPENDENCIES, MESON_SYSTEM_DEPENDENCIES)
    for packages in mapping.values()
    for package in packages
) | REVIEWED_BUILD_TOOL_PACKAGES
CMAKE_SOURCE_DEPENDENCIES = {
    "absl": {
        "url": "https://github.com/abseil/abseil-cpp.git",
        "commit": "d38452e1ee03523a208362186fd42248ff2609f6",
    },
    "cpuinfo": {
        "url": "https://github.com/pytorch/cpuinfo.git",
        "commit": "8ce83db858065145192c97af90cb668ad72a12e9",
        "detection_markers": ("cpuinfo_source_dir", "github.com/pytorch/cpuinfo"),
        "cmake_source_variable": "CPUINFO_SOURCE_DIR",
        "build_separately": False,
    },
    "fxdiv": {
        "url": "https://github.com/Maratyszcza/FXdiv.git",
        "commit": "63058eff77e11aa15bf531df5dd34395ec3017c8",
        "cmake_source_variable": "FXDIV_SOURCE_DIR",
        "build_separately": False,
    },
    "pthreadpool": {
        "url": "https://github.com/google/pthreadpool.git",
        "commit": "15a6644ba1c45f1acc16ac1e883efc3e56c6bed2",
        "detection_markers": (
            "pthreadpool_source_dir",
            "github.com/google/pthreadpool",
        ),
        "cmake_source_variable": "PTHREADPOOL_SOURCE_DIR",
        "build_separately": False,
        "requires": ("fxdiv",),
    },
}


def detect_build_system(source: Path) -> str:
    for name, markers in BUILD_SYSTEM_MARKERS:
        if any((source / marker).is_file() for marker in markers):
            return name
    raise PipelineError("no supported CMake, Meson, Autotools, or Cargo build was detected")


def _has_root_cmake_interface_library(source: Path) -> bool:
    """Allow archive-free linking only for an explicit root header-only target."""
    root = source / "CMakeLists.txt"
    if source.is_symlink() or root.is_symlink() or not root.is_file():
        return False
    try:
        if root.stat().st_size > 250_000:
            return False
        text = root.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    text = re.sub(r"#\[(=*)\[.*?\]\1\]", "", text, flags=re.DOTALL)
    active = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    return bool(re.search(
        r"(?im)^[ \t]*add_library[ \t]*\([ \t]*"
        r"[A-Za-z_][A-Za-z0-9_.+-]*[ \t]+INTERFACE[ \t]*\)",
        active,
    ))


def create_generic_project(
    *,
    job_dir: Path,
    source: Path,
    project_dir: Path,
    project_name: str,
    pipeline: dict[str, Any],
    progress: Callable[[str], None] | None = None,
    native: bool = False,
    base_image: str = "ubuntu:24.04",
    cancel_event=None,
) -> dict[str, Any]:
    progress = progress or (lambda _: None)
    build_system = detect_build_system(source)
    system_dependencies = _detect_system_dependencies(source, build_system)
    source_dependencies = _detect_source_dependencies(source, build_system)
    allow_header_only_cmake = (
        build_system == "cmake" and _has_root_cmake_interface_library(source)
    )
    project_dir.mkdir(parents=True, exist_ok=False)
    harness, origin, usage, candidate = _obtain_harness(
        job_dir, source, project_name, pipeline, progress,
        cancel_event=cancel_event,
    )
    harness_path = project_dir / "generic_harness.cc"
    harness_path.write_text(harness, encoding="utf-8")
    harness_path.chmod(0o644)
    (project_dir / "Dockerfile").write_text(
        _dockerfile(
            build_system,
            base_image if native else None,
            system_dependencies,
            source_dependencies,
        ),
        encoding="utf-8",
    )
    support_sources, support_include_dirs = _candidate_support_dependencies(
        source, candidate
    )
    harness_language = _candidate_harness_language(candidate, origin)
    build_script = _build_script(
        build_system,
        _candidate_include_dir(candidate),
        support_sources,
        harness_language,
        support_include_dirs,
        source_dependencies,
        allow_header_only_cmake=allow_header_only_cmake,
    )
    build_path = project_dir / "build.sh"
    build_path.write_text(build_script, encoding="utf-8")
    build_path.chmod(0o755)
    (project_dir / "project.yaml").write_text(
        "homepage: https://example.invalid/local-generated-integration\n"
        "language: c++\n"
        "primary_contact: local-only@example.invalid\n"
        "auto_ccs: []\n",
        encoding="utf-8",
    )
    return {
        "schema_version": 1,
        "created_at": utc_now(),
        "project": project_name,
        "build_system": build_system,
        "execution_mode": "native_container" if native else "oss_fuzz",
        "base_image": base_image if native else "gcr.io/oss-fuzz-base/base-builder",
        "harness_origin": origin,
        "candidate": candidate,
        "harness_language": harness_language,
        "support_sources": support_sources,
        "support_include_dirs": support_include_dirs,
        "system_dependencies": system_dependencies,
        "source_dependencies": source_dependencies,
        "allow_header_only_cmake": allow_header_only_cmake,
        "ai_usage": usage,
        "harness_sha256": hashlib.sha256(harness.encode()).hexdigest(),
        "build_script_sha256": hashlib.sha256(build_script.encode()).hexdigest(),
        "repair_attempts": [],
    }


def repair_generic_harness(
    *,
    job_dir: Path,
    source: Path,
    project_dir: Path,
    pipeline: dict[str, Any],
    build_error: str,
    attempt: int,
    cancel_event=None,
) -> dict[str, Any]:
    record_path = job_dir / "artifacts" / "generic-integration.json"
    record = _read_json(record_path)
    inferred_dependencies = _infer_system_dependencies_from_build_error(build_error)
    current_dependencies = set(record.get("system_dependencies") or ())
    added_dependencies = sorted(inferred_dependencies - current_dependencies)
    if added_dependencies:
        current_dependencies.update(added_dependencies)
        native_base_image = None
        if record.get("execution_mode") == "native_container":
            native_base_image = str(record.get("base_image") or "ubuntu:24.04")
        dockerfile = _dockerfile(
            str(record["build_system"]),
            native_base_image,
            sorted(current_dependencies),
            tuple(record.get("source_dependencies") or ()),
        )
        dockerfile_path = project_dir / "Dockerfile"
        dockerfile_path.write_text(dockerfile, encoding="utf-8")
        item = {
            "attempt": attempt,
            "created_at": utc_now(),
            "ai_usage": {},
            "repair_kind": "deterministic_system_dependency",
            "added_system_dependencies": added_dependencies,
            "requires_clean_build": True,
            "build_error_sha256": hashlib.sha256(build_error.encode()).hexdigest(),
        }
        record["system_dependencies"] = sorted(current_dependencies)
        record["dockerfile_sha256"] = hashlib.sha256(dockerfile.encode()).hexdigest()
        record.setdefault("repair_attempts", []).append(item)
        _write_json(record_path, record)
        return item
    candidate = record.get("candidate") or {}
    harness_origin = str(record.get("harness_origin", ""))
    if harness_origin.startswith("existing:"):
        allow_header_only_cmake = (
            record.get("build_system") == "cmake"
            and _has_root_cmake_interface_library(source)
        )
        discovered_sources, discovered_include_dirs = (
            _candidate_support_dependencies(source, candidate)
        )
        support_sources = sorted(
            set(record.get("support_sources") or []) | set(discovered_sources)
        )
        support_include_dirs = sorted(
            set(record.get("support_include_dirs") or [])
            | set(discovered_include_dirs)
        )
        harness_language = str(
            record.get("harness_language")
            or _candidate_harness_language(candidate, harness_origin)
        )
        build_script = _build_script(
            str(record["build_system"]),
            _candidate_include_dir(candidate),
            support_sources,
            harness_language,
            support_include_dirs,
            tuple(record.get("source_dependencies") or ()),
            allow_header_only_cmake=allow_header_only_cmake,
        )
        build_path = project_dir / "build.sh"
        build_path.write_text(build_script, encoding="utf-8")
        build_path.chmod(0o755)
        item = {
            "attempt": attempt,
            "created_at": utc_now(),
            "ai_usage": {},
            "repair_kind": "deterministic_harness_include_path",
            "build_error_sha256": hashlib.sha256(build_error.encode()).hexdigest(),
        }
        record["build_script_sha256"] = hashlib.sha256(
            build_script.encode()
        ).hexdigest()
        record["harness_language"] = harness_language
        record["allow_header_only_cmake"] = allow_header_only_cmake
        record["support_sources"] = support_sources
        record["support_include_dirs"] = support_include_dirs
        record.setdefault("repair_attempts", []).append(item)
        _write_json(record_path, record)
        return item
    if not candidate.get("file"):
        candidate = _select_public_candidate(source)
    _record_generation_candidate(job_dir, candidate)
    context = _generation_context(source, candidate)
    harness_path = project_dir / "generic_harness.cc"
    prior = harness_path.read_text(encoding="utf-8", errors="replace")
    prompt = generation_prompt(
        project=str(record["project"]), language="C++", fuzz_target="generic_fuzzer",
        candidate=candidate, context=context, existing_harness=prior,
        prior_code=prior, build_error=build_error[-8000:],
    )
    output = job_dir / "artifacts" / f"generic-integration-repair-{attempt}"
    if output.exists():
        shutil.rmtree(output)
    response, usage = invoke_oss_fuzz_gen_adapter(
        pipeline, prompt, output, cancel_event=cancel_event
    )
    code = extract_harness_code(response)
    validation = validate_generated_harness(code, candidate)
    harness_path.write_text(code, encoding="utf-8")
    harness_path.chmod(0o644)
    for integration_name in ("oss-fuzz", "native"):
        mirror = job_dir / "integration" / integration_name / "generic_harness.cc"
        if mirror.parent.is_dir():
            mirror.write_text(code, encoding="utf-8")
            mirror.chmod(0o644)
    item = {
        "attempt": attempt,
        "created_at": utc_now(),
        "ai_usage": usage,
        "validation": validation,
        "build_error_sha256": hashlib.sha256(build_error.encode()).hexdigest(),
    }
    record["candidate"] = candidate
    record["harness_sha256"] = validation["sha256"]
    record.setdefault("repair_attempts", []).append(item)
    _write_json(record_path, record)
    return item


def _obtain_harness(
    job_dir: Path,
    source: Path,
    project: str,
    pipeline: dict[str, Any],
    progress: Callable[[str], None],
    *,
    cancel_event=None,
) -> tuple[str, str, dict[str, int], dict[str, Any]]:
    exclusions = _read_optional_json(
        job_dir / "artifacts" / "harness-exclusions.json"
    )
    excluded_paths = {
        str(value)
        for value in exclusions.get("paths") or []
        if isinstance(value, str)
    }
    existing = _find_existing_harness(source, excluded_paths)
    if existing is not None:
        code = existing.read_text(encoding="utf-8", errors="replace")
        relative = existing.relative_to(source).as_posix()
        candidate = {
            "id": hashlib.sha256(relative.encode()).hexdigest()[:16],
            "file": relative,
            "signature": "LLVMFuzzerTestOneInput(const uint8_t*, size_t)",
        }
        validate_generated_harness(code, candidate)
        return code, f"existing:{relative}", {}, candidate
    excluded_candidate_ids = {
        str(value) for value in exclusions.get("candidate_ids") or []
        if isinstance(value, str)
    }
    candidate = _select_public_candidate(source, excluded_candidate_ids)
    _record_generation_candidate(job_dir, candidate)
    context = _generation_context(source, candidate)
    prompt = generation_prompt(
        project=project,
        language="C++",
        fuzz_target="generic_fuzzer",
        candidate=candidate,
        context=context,
        existing_harness=(
            "#include <cstddef>\n#include <cstdint>\n"
            "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t*, size_t);\n"
        ),
    )
    output = job_dir / "artifacts" / "generic-integration-generation"
    if output.exists():
        shutil.rmtree(output)
    progress(f"{job_dir.name}: generating initial harness for {candidate['signature']}")
    response, usage = invoke_oss_fuzz_gen_adapter(
        pipeline, prompt, output, cancel_event=cancel_event
    )
    code = extract_harness_code(response)
    validate_generated_harness(code, candidate)
    return code, "codex_oss_fuzz_gen_adapter", usage, candidate


def _record_generation_candidate(job_dir: Path, candidate: dict[str, Any]) -> None:
    path = job_dir / "artifacts" / "generic-integration-selection.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(path, {
        "schema_version": 1,
        "created_at": utc_now(),
        "candidate": candidate,
    })


def _generation_context(source: Path, candidate: dict[str, Any]) -> str:
    """Include a bounded public memory-stream API for stream-based targets."""
    primary = source_context(source, candidate, radius=140)
    signature = str(candidate.get("signature") or "")
    if not re.search(
        r"\b(?:[A-Za-z_]\w*::)*(?:[A-Za-z_]\w*)?(?:InputStream|"
        r"IOStream|MemoryStream|BoundedStream|StreamReader|istream|streambuf)\s*[*&]",
        signature,
        re.IGNORECASE,
    ):
        return primary
    target = Path(str(candidate.get("file") or ""))
    target_text = (source / target).read_text(encoding="utf-8", errors="replace")
    target_type = target.stem
    base_names = {
        match.group(1).casefold()
        for match in re.finditer(
            r"\b(?:class|struct)\s+(?:[A-Za-z_]\w*\s+){0,2}"
            + re.escape(target_type)
            + r"\s*:\s*public\s+([A-Za-z_]\w*)",
            target_text,
        )
    }
    adapters: list[tuple[int, Path]] = []
    bases: list[Path] = []
    excluded = {"bench", "benchmark", "benchmarks", "examples", "test", "tests",
                "third_party", "third-party", "tools", "vendor", "internal", "private"}
    for scanned, path in enumerate(source.rglob("*")):
        if scanned >= 20_000:
            break
        if path == source / target or path.is_symlink() or not path.is_file():
            continue
        if path.suffix.casefold() not in HEADER_SUFFIXES:
            continue
        try:
            if path.stat().st_size > 100_000:
                continue
        except OSError:
            continue
        relative = path.relative_to(source)
        if {part.casefold() for part in relative.parts[:-1]} & excluded:
            continue
        stem = path.stem.casefold()
        memory_like = bool(re.search(
            r"(?:memory|buffer|span|byte|string).*(?:stream|reader)"
            r"|(?:stream|reader).*(?:memory|buffer|span|byte|string)",
            stem,
        ))
        if memory_like:
            adapters.append((0 if "memory" in stem else 1, path))
        elif stem in base_names:
            bases.append(path)
    selected = [path for _, path in sorted(adapters, key=lambda item: (item[0],
        _public_header_rank(source, item[1])))[:1]]
    selected += sorted(bases, key=lambda path: _public_header_rank(source, path))[:1]
    if not selected:
        return primary
    related: list[str] = []
    for path in selected:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        stem = path.stem.casefold()
        class_line = next((number for number, line in _accessible_header_lines(lines)
                           if re.search(r"\b(?:class|struct)\b", line)
                           and re.search(r"\b" + re.escape(stem) + r"\b", line,
                                         re.IGNORECASE)
                           and not line.rstrip().endswith(";")), 1)
        snippet = [f"Related public header: {path.relative_to(source).as_posix()}"]
        for number, visible in _accessible_header_lines(lines):
            if number < max(1, class_line - 3) or number > class_line + 100:
                continue
            if visible.strip():
                snippet.append(f"{number:05d}: {visible}")
        related.append("\n".join(snippet)[:2600])
    return (primary[:12000] + "\n\n" + "\n\n".join(related))[:18000]


def _find_existing_harness(
    source: Path, excluded_paths: set[str] | None = None
) -> Path | None:
    excluded_paths = excluded_paths or set()
    candidates: list[tuple[tuple[int, int, str], Path]] = []
    for path in sorted(source.rglob("*")):
        try:
            relative = path.relative_to(source).as_posix()
        except ValueError:
            continue
        if relative in excluded_paths:
            continue
        if path.is_symlink() or not path.is_file() or path.suffix.casefold() not in SOURCE_SUFFIXES:
            continue
        try:
            if path.stat().st_size > 500_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            definitions = re.findall(
                r"\bLLVMFuzzerTestOneInput\s*\([^;{}]*\)\s*\{",
                text,
                re.DOTALL,
            )
            if len(definitions) != 1:
                continue
            lowered = text.casefold()
            name = path.stem.casefold()
            relative_parts = {
                part.casefold() for part in Path(relative).parts[:-1]
            }
            penalty = 0
            if relative_parts & {
                "third_party",
                "third-party",
                "external",
                "extern",
                "vendor",
                "vendored",
            }:
                penalty += 250
            if "static_linking_only" in lowered:
                penalty += 100
            if re.search(r'#\s*include\s*[<"][^>"\n]*(?:private|internal)', lowered):
                penalty += 60
            if "simple" in name:
                penalty -= 30
            if any(value in name for value in ("decompress", "decode", "parse", "read")):
                penalty -= 20
            if "compress" in name and "decompress" not in name:
                penalty -= 5
            candidates.append(
                ((penalty, len(text.splitlines()), path.as_posix()), path)
            )
        except OSError:
            continue
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0])[1]


def _select_public_candidate(
    source: Path, excluded_candidate_ids: set[str] | None = None,
) -> dict[str, Any]:
    excluded_candidate_ids = excluded_candidate_ids or set()
    prototype = re.compile(
        r'^\s*(?:extern\s+"C"\s+)?'
        r'(?P<result>[A-Za-z_][\w:<>,*&\s]*)\s+'
        r'(?P<name>[A-Za-z_][A-Za-z0-9_:]*)\s*\([^;]*\)\s*'
        r'(?:(?:const|noexcept|override|final)\s*)*;\s*$'
    )
    rejected = {
        "alignof",
        "decltype",
        "for",
        "free",
        "if",
        "main",
        "malloc",
        "operator",
        "sizeof",
        "while",
    }
    headers = (
        path
        for path in source.rglob("*")
        if not path.is_symlink()
        and path.is_file()
        and path.suffix.casefold() in HEADER_SUFFIXES
    )
    excluded_directories = {
        "bench", "benchmark", "benchmarks", "examples", "test", "tests",
        "third_party", "third-party", "tools", "vendor",
        "detail", "details", "impl", "implementation", "internal", "private",
    }
    candidates: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    macro_candidates: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    for path in sorted(headers, key=lambda item: _public_header_rank(source, item)):
        relative_parts = {
            part.casefold() for part in path.relative_to(source).parts[:-1]
        }
        if relative_parts & excluded_directories:
            continue
        try:
            if path.stat().st_size > 300_000:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, signature in _public_function_declarations(lines):
            match = prototype.match(signature)
            if (
                not match
                or match.group("name").split("::")[-1] in rejected
                or _is_lifetime_api(match.group("name"))
                or not _is_declaration_result(match.group("result"))
            ):
                continue
            candidate = {
                "id": hashlib.sha256(f"{path}:{number}".encode()).hexdigest()[:16],
                "file": path.relative_to(source).as_posix(),
                "local_symbol_line": number,
                "signature": signature[:1000],
            }
            if candidate["id"] in excluded_candidate_ids:
                continue
            input_rank = _candidate_input_rank(candidate["signature"], match.group("name"))
            if input_rank == 4:
                continue
            candidates.append((
                (
                    input_rank,
                    _public_header_rank(source, path),
                    number,
                ),
                candidate,
            ))
        for number, name, parameters in _public_macro_definitions(lines):
            candidate = {
                "id": hashlib.sha256(f"{path}:{number}".encode()).hexdigest()[:16],
                "file": path.relative_to(source).as_posix(),
                "local_symbol_line": number,
                "signature": f"{name}({parameters})"[:1000],
                "candidate_kind": "macro",
            }
            if candidate["id"] in excluded_candidate_ids:
                continue
            macro_candidates.append((
                (
                    _public_macro_rank(name, parameters),
                    _public_header_rank(source, path),
                    number,
                ),
                candidate,
            ))
    if candidates:
        return min(candidates, key=lambda item: item[0])[1]
    if macro_candidates:
        return min(macro_candidates, key=lambda item: item[0])[1]
    raise PipelineError("no existing harness or public function or macro API was found")


def _is_declaration_result(result: str) -> bool:
    """Reject expression prefixes that resemble a function return type."""
    if re.search(
        r"\b(?:return|co_return|throw|delete|new|if|else|for|while|"
        r"switch|case|goto|break|continue|using|typedef|sizeof|alignof)\b",
        result,
    ):
        return False
    depth = 0
    for character in result:
        if character == "<":
            depth += 1
        elif character == ">":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _public_macro_definitions(lines: list[str]):
    """Yield named function-like macros, never their replacement text."""
    pattern = re.compile(
        r"^\s*#\s*define\s+(?P<name>[A-Z][A-Z0-9_]*)"
        r"\((?P<parameters>[^()]*)\)(?=\s|$)"
    )
    parameter = re.compile(r"(?:[A-Za-z_]\w*|\.\.\.|[A-Za-z_]\w*\.\.\.)$")
    in_comment = False
    in_directive = False
    for number, raw_line in enumerate(lines, 1):
        visible, _, in_comment = _scan_header_line(raw_line, in_comment)
        if not in_directive:
            match = pattern.match(visible)
            if match:
                parameters = match.group("parameters").strip()
                names = [value.strip() for value in parameters.split(",")]
                if all(parameter.fullmatch(value) for value in names):
                    yield number, match.group("name"), parameters
        in_directive = (
            (in_directive or visible.lstrip().startswith("#"))
            and raw_line.rstrip().endswith(chr(92))
        )


def _public_macro_rank(name: str, parameters: str) -> tuple[int, int, int]:
    parts = name.split("_")
    helper_parts = {
        "ALIAS", "DEF", "DETAIL", "DETAILS", "FWD", "HELPER", "IMPL",
        "INTERNAL", "OVERLOAD", "PRIVATE",
    }
    helper = int(bool(set(parts) & helper_parts))
    return (helper, -len(parameters.split(",")), len(parts))


def _candidate_input_rank(signature: str, name: str) -> int:
    """Prefer parsing bytes or an input stream over state-only methods."""
    arguments = signature.partition("(")[2].rpartition(")")[0].strip()
    if not arguments or arguments == "void":
        return 4
    words = _symbol_words(name)
    mutable_read_buffer = "read" in words and any(
        re.search(
            r"\b(?:(?:unsigned|signed)\s+)?(?:char|byte|u?int8_t|void)\s*\*",
            parameter,
            re.IGNORECASE,
        ) and not re.search(r"\bconst\b", parameter)
        for parameter in arguments.split(",")
    )
    if mutable_read_buffer:
        # Stream::read(dst, size) fills an output buffer; fuzz bytes never
        # reach a parser through that API alone.
        return 4
    has_byte_input = bool(re.search(
        r"\b(?:basic_string|string(?:_view)?|span|vector)\b"
        r"|\b(?:(?:const|unsigned)\s+)*(?:std::)?(?:char|byte|u?int8_t)\s*[*&]",
        arguments,
        re.IGNORECASE,
    ))
    has_stream_input = bool(re.search(
        r"\b(?:[A-Za-z_]\w*::)*(?:[A-Za-z_]\w*)?(?:InputStream|"
        r"IOStream|MemoryStream|BoundedStream|StreamReader|istream|streambuf)\s*[*&]",
        arguments,
        re.IGNORECASE,
    ))
    parser_name = bool(set(words) & {
        "parse", "decode", "deserialize", "deserialise", "tokenize",
        "tokenise", "lex", "read", "load",
    }) or ("from" in words and bool(set(words) & {
        "json", "string", "bytes", "stream",
    }))
    reader_factory = bool(re.search(r"\b(?:create|make|open|from\w*)$", name, re.IGNORECASE)) and bool(
        re.search(r"reader|parser|decoder|deseriali[sz]er", signature, re.IGNORECASE)
    )
    if words and words[0] in {"set", "get", "is", "has", "query"}:
        input_field = bool(set(words) & {
            "input", "data", "buffer", "bytes", "payload", "content", "stream",
        })
        has_length = bool(re.search(r"\b(?:size|length|count|len)\b", arguments,
                                    re.IGNORECASE))
        if not has_stream_input and not (has_byte_input and input_field and has_length):
            return 4
    if has_byte_input:
        return 0 if parser_name else 2
    if has_stream_input:
        return 1 if parser_name or reader_factory else 2
    return 3


def _is_lifetime_api(name: str) -> bool:
    """Do not fuzz object teardown as if it were an input parser."""
    words = _symbol_words(name)
    if words[0] in {"parse", "decode", "deserialize", "read", "load"}:
        return False
    return any(word in {
        "clear", "cleanup", "close", "dealloc", "deallocate", "delete",
        "destroy", "dispose", "finalize", "free", "release", "reset",
        "shutdown", "terminate",
    } for word in words)


def _symbol_words(name: str) -> list[str]:
    """Split identifier words without finding parser verbs inside unrelated words."""
    symbol = name.split("::")[-1]
    symbol = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", symbol)
    symbol = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", symbol)
    return [word.casefold() for word in symbol.split("_") if word]


def _public_function_declarations(lines: list[str]):
    """Join short public declarations without crossing access or scope boundaries."""
    fragments: list[str] = []
    start = 0
    previous = 0
    for number, visible in _accessible_header_lines(lines):
        if previous and number != previous + 1:
            fragments = []
        previous = number
        fragment = visible.strip()
        if not fragment:
            continue
        if "{" in fragment and "(" not in " ".join(fragments + [fragment]):
            fragments = []
            continue
        if fragment.startswith("}") or fragment in {"public:", "protected:", "private:"}:
            fragments = []
            continue
        if not fragments:
            start = number
        fragments.append(fragment)
        statement = " ".join(fragments)
        if len(statement) > 1000 or len(fragments) > 16:
            fragments = []
            continue
        if ";" in fragment:
            if statement.endswith(";") and statement.count(";") == 1:
                yield start, statement
            fragments = []


def _accessible_header_lines(lines: list[str]):
    """Yield declarations outside non-public C++ class and struct sections."""
    scopes: list[dict[str, str]] = []
    declaration = ""
    in_comment = False
    tokens = re.compile(r"\{|\}|;|\b(?:public|protected|private)\s*:")
    class_kind = re.compile(r"\b(class|struct|union)\s+[A-Za-z_]\w*")
    in_directive = False
    for number, raw_line in enumerate(lines, 1):
        if in_directive or raw_line.lstrip().startswith("#"):
            _, _, in_comment = _scan_header_line(raw_line, in_comment)
            in_directive = raw_line.rstrip().endswith(chr(92))
            continue
        visible, structural, in_comment = _scan_header_line(raw_line, in_comment)
        if all(scope["kind"] == "other" or scope["access"] == "public" for scope in scopes):
            yield number, visible
        cursor = 0
        for token in tokens.finditer(structural):
            declaration += structural[cursor:token.start()]
            value = token.group()
            if value == "{":
                matches = list(class_kind.finditer(declaration))
                kind = matches[-1].group(1) if matches else "other"
                scopes.append({
                    "kind": kind,
                    "access": "private" if kind == "class" else "public",
                })
                declaration = ""
            elif value == "}":
                if scopes:
                    scopes.pop()
                declaration = ""
            elif value == ";":
                declaration = ""
            else:
                if scopes and scopes[-1]["kind"] != "other":
                    scopes[-1]["access"] = value.split(":", 1)[0].strip()
                declaration = ""
            cursor = token.end()
        declaration = (declaration + structural[cursor:])[-2000:]


def _scan_header_line(line: str, in_block_comment: bool) -> tuple[str, str, bool]:
    visible: list[str] = []
    structural: list[str] = []
    index = 0
    while index < len(line):
        if in_block_comment:
            end = line.find("*/", index)
            if end < 0:
                spaces = " " * (len(line) - index)
                visible.append(spaces)
                structural.append(spaces)
                break
            spaces = " " * (end + 2 - index)
            visible.append(spaces)
            structural.append(spaces)
            in_block_comment = False
            index = end + 2
        elif line.startswith("//", index):
            spaces = " " * (len(line) - index)
            visible.append(spaces)
            structural.append(spaces)
            break
        elif line.startswith("/*", index):
            visible.append("  ")
            structural.append("  ")
            in_block_comment = True
            index += 2
        elif line[index] in {'"', "'"}:
            start = index
            quote = line[index]
            index += 1
            while index < len(line):
                character = line[index]
                index += 1
                if character == chr(92) and index < len(line):
                    index += 1
                elif character == quote:
                    break
            visible.append(line[start:index])
            structural.append(" " * (index - start))
        else:
            visible.append(line[index])
            structural.append(line[index])
            index += 1
    return "".join(visible), "".join(structural), in_block_comment



def _public_header_rank(source: Path, path: Path) -> tuple[int, int, int, str]:
    relative = path.relative_to(source)
    parts = tuple(part.casefold() for part in relative.parts[:-1])
    low_value = {
        "bench",
        "benchmark",
        "benchmarks",
        "examples",
        "internal",
        "src",
        "test",
        "tests",
        "third_party",
        "tools",
        "vendor",
    }
    return (
        int(bool(set(parts) & low_value)),
        int("include" not in parts and parts != ()),
        len(parts),
        relative.as_posix().casefold(),
    )


def _detect_system_dependencies(source: Path, build_system: str) -> list[str]:
    if build_system == "cmake":
        packages = _declared_cmake_packages(source)
        mapping = CMAKE_SYSTEM_DEPENDENCIES
    elif build_system == "meson":
        packages = _declared_required_meson_packages(source)
        mapping = MESON_SYSTEM_DEPENDENCIES
    else:
        packages = set()
        mapping = {}
    dependencies: set[str] = set()
    for package in packages:
        dependencies.update(mapping.get(package, ()))
    return sorted(dependencies)


def _detect_source_dependencies(source: Path, build_system: str) -> list[str]:
    if build_system != "cmake":
        return []
    packages = _declared_cmake_packages(source)
    cmake_text = _cmake_metadata_text(source).casefold()
    dependencies = packages & CMAKE_SOURCE_DEPENDENCIES.keys()
    for name, metadata in CMAKE_SOURCE_DEPENDENCIES.items():
        markers = metadata.get("detection_markers") or ()
        if any(str(marker).casefold() in cmake_text for marker in markers):
            dependencies.add(name)
    pending = list(dependencies)
    while pending:
        name = pending.pop()
        for required in CMAKE_SOURCE_DEPENDENCIES[name].get("requires") or ():
            if required not in CMAKE_SOURCE_DEPENDENCIES or required in dependencies:
                continue
            dependencies.add(required)
            pending.append(required)
    return sorted(dependencies)


def _declared_cmake_packages(source: Path) -> set[str]:
    text = _cmake_metadata_text(source)
    return {
        match.group(1).casefold()
        for match in re.finditer(
            r"\bfind_package\s*\(\s*([A-Za-z0-9_+.-]+)", text, re.IGNORECASE
        )
    }


def _cmake_metadata_text(source: Path) -> str:
    # Walk breadth-first so root and immediate subprojects are examined before
    # deep vendored trees. Never traverse symlinks into unrelated host files.
    if source.is_symlink() or not source.is_dir():
        return ""
    files: list[Path] = []
    directories = [source]
    cmake_dir = source / "cmake"
    cursor = 0
    while cursor < len(directories) and len(files) < 100:
        directory = directories[cursor]
        cursor += 1
        try:
            with os.scandir(directory) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in children:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in {".git", ".venv"} and len(directories) < 500:
                        directories.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                path = Path(entry.path)
                is_cmake_script = entry.name.endswith(".cmake") and (
                    directory == cmake_dir or cmake_dir in directory.parents
                )
                if entry.name == "CMakeLists.txt" or is_cmake_script:
                    files.append(path)
                    if len(files) >= 100:
                        break
            except OSError:
                continue
    chunks: list[str] = []
    total_bytes = 0
    for path in files:
        try:
            size = path.stat().st_size
            if size > 250_000 or total_bytes + size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total_bytes += size
        chunks.append(text)
    return "\n".join(chunks)


def _declared_required_meson_packages(source: Path) -> set[str]:
    text = _meson_metadata_text(source)
    # Meson dependencies are required unless explicitly marked optional.
    # Keep the scan bounded and use only names in the reviewed package map.
    packages = set()
    for match in re.finditer(
        r"\bdependency\s*\(\s*['\"]([A-Za-z0-9_+.-]+)['\"]"
        r"(?P<options>(?:(?!\)).){0,500})\)",
        text,
        re.IGNORECASE | re.DOTALL,
    ):
        if not re.search(
            r"\brequired\s*:\s*false\b", match.group("options"), re.IGNORECASE
        ):
            packages.add(match.group(1).casefold())
    lowered = text.casefold()
    if "no lua implementation was found" in lowered:
        packages.add("lua5.4")
    return packages


def _meson_metadata_text(source: Path) -> str:
    files = [
        path
        for path in sorted(source.rglob("meson.build"))
        if path.is_file() and not path.is_symlink()
    ]
    chunks: list[str] = []
    total_bytes = 0
    for path in files[:100]:
        try:
            size = path.stat().st_size
            if size > 250_000 or total_bytes + size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total_bytes += size
        chunks.append(text)
    return "\n".join(chunks)


def _infer_system_dependencies_from_build_error(build_error: str) -> set[str]:
    error = build_error.casefold()
    dependencies: set[str] = set()
    if "no lua implementation was found" in error:
        dependencies.add("liblua5.4-dev")
    if re.search(
        r"\bcould not find gtest\s*\(\s*missing:\s*"
        r"gtest_library\s+gtest_include_dir\s+gtest_main_library\s*\)",
        error,
    ):
        dependencies.update(CMAKE_SYSTEM_DEPENDENCIES["gtest"])
    for tool in REVIEWED_BUILD_TOOL_PACKAGES - {"python3-yaml"}:
        if re.search(
            rf"\berror:\s+program\s+['\"]?{re.escape(tool)}['\"]?\s+not\s+found",
            error,
        ):
            dependencies.add(tool)
    if re.search(r"no module named ['\"]yaml['\"]", error):
        dependencies.add("python3-yaml")
    for dependency, packages in MESON_SYSTEM_DEPENDENCIES.items():
        escaped = re.escape(dependency.casefold())
        if re.search(
            rf"error:\s+dependency\s+['\"]{escaped}['\"]\s+not\s+found",
            error,
        ):
            dependencies.update(packages)
    return dependencies & REVIEWED_SYSTEM_PACKAGES


def _dockerfile(
    build_system: str,
    native_base_image: str | None = None,
    system_dependencies: list[str] | tuple[str, ...] = (),
    source_dependencies: list[str] | tuple[str, ...] = (),
) -> str:
    packages = {
        # CMake projects commonly generate sources and tables with Python at
        # configure time, including native ARM microkernel projects.
        "cmake": "cmake ninja-build pkg-config python3",
        "meson": "meson ninja-build pkg-config python3 python3-yaml ragel",
        "autotools": "autoconf automake libtool make pkg-config",
        "cargo": "cargo rustc pkg-config",
    }[build_system]
    allowed_dependencies = sorted(
        {
            dependency
            for dependency in system_dependencies
            if dependency in REVIEWED_SYSTEM_PACKAGES
        }
    )
    dependency_packages = (
        " " + " ".join(allowed_dependencies) if allowed_dependencies else ""
    )
    allowed_sources = sorted(
        {
            dependency
            for dependency in source_dependencies
            if dependency in CMAKE_SOURCE_DEPENDENCIES
        }
    )
    source_package = " git" if allowed_sources else ""
    native_tools = " flex bison" if allowed_sources else " git flex bison"
    source_checkout = ""
    for name in allowed_sources:
        dependency = CMAKE_SOURCE_DEPENDENCIES[name]
        source_checkout += f"""RUN git clone --filter=blob:none {dependency['url']} /opt/fuzz-dependencies/{name} \\
    && git -C /opt/fuzz-dependencies/{name} checkout --detach {dependency['commit']} \\
    && rm -rf /opt/fuzz-dependencies/{name}/.git
"""
    if native_base_image is None:
        return f"""FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    {packages}{dependency_packages}{source_package} \
    && rm -rf /var/lib/apt/lists/*
{source_checkout}COPY --chmod=0755 build.sh $SRC/build.sh
COPY --chmod=0644 generic_harness.cc $SRC/generic_harness.cc
WORKDIR $SRC/project
"""
    if not re.fullmatch(r"[A-Za-z0-9./:_-]{3,200}", native_base_image):
        raise PipelineError("native builder image reference is invalid")
    return f"""FROM {native_base_image}
ARG FUZZ_UID=1000
ARG FUZZ_GID=1000
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates clang lld llvm file libclang-rt-dev libc++-dev libc++abi-dev \
    build-essential passwd {packages}{dependency_packages}{source_package}{native_tools} \
    && rm -rf /var/lib/apt/lists/*
RUN if ! getent group "$FUZZ_GID" >/dev/null; then groupadd --gid "$FUZZ_GID" fuzzbuild; fi \
    && if ! getent passwd "$FUZZ_UID" >/dev/null; then useradd --uid "$FUZZ_UID" \
      --gid "$FUZZ_GID" --no-create-home --shell /usr/sbin/nologin fuzzbuild; fi
{source_checkout}ENV SRC=/src WORK=/work OUT=/out \
    CC=clang CXX=clang++ \
    CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,fuzzer-no-link" \
    CXXFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,fuzzer-no-link" \
    LIB_FUZZING_ENGINE="-fsanitize=fuzzer,address"
RUN mkdir -p /src/project /work /out
COPY --chmod=0755 build.sh /src/build.sh
COPY --chmod=0644 generic_harness.cc /src/generic_harness.cc
WORKDIR /src/project
"""


def _candidate_include_dir(candidate: dict[str, Any]) -> str:
    value = Path(str(candidate.get("file") or "")).parent.as_posix()
    if value in {"", "."}:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9_./+-]{1,300}", value):
        return ""
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        return ""
    return value


def _safe_relative_source(value: str) -> str | None:
    if not re.fullmatch(r"[A-Za-z0-9_./+-]{1,300}", value):
        return None
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        return None
    return path.as_posix()


def _candidate_support_sources(
    source: Path, candidate: dict[str, Any]
) -> list[str]:
    support_sources, _ = _candidate_support_dependencies(source, candidate)
    return support_sources


def _candidate_support_dependencies(
    source: Path, candidate: dict[str, Any]
) -> tuple[list[str], list[str]]:
    relative = _safe_relative_source(str(candidate.get("file") or ""))
    if not relative:
        return [], []
    harness = source / relative
    source_root = source.resolve()
    support: set[str] = set()
    include_directories: set[str] = set()
    pending = [harness]
    visited: set[Path] = set()
    header_index: dict[str, list[Path]] | None = None
    while pending and len(visited) < 100:
        current = pending.pop()
        resolved_current = current.resolve()
        if resolved_current in visited:
            continue
        visited.add(resolved_current)
        try:
            text = current.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            current_relative = current.resolve().relative_to(source_root).as_posix()
        except ValueError:
            current_relative = ""
        for include in re.findall(
            r'^\s*#\s*include\s*"([^"\n]+)"', text, re.MULTILINE
        ):
            header = _resolve_project_header(
                source_root, current.parent, include, header_index
            )
            if header is None and header_index is None:
                header_index = _project_header_index(source_root)
                header = _resolve_project_header(
                    source_root, current.parent, include, header_index
                )
            if header is None:
                continue
            include_root = header
            for _ in Path(include).parts:
                include_root = include_root.parent
            try:
                include_directory = include_root.relative_to(source_root).as_posix()
            except ValueError:
                include_directory = "."
            if include_directory != ".":
                include_directories.add(include_directory)
            pending.append(header)
            header_relative = header.relative_to(source_root).as_posix()
            support_context = (
                current_relative in support
                or _is_harness_support_path(header_relative)
            )
            for suffix in SOURCE_SUFFIXES:
                companion = header.with_suffix(suffix)
                if (
                    not support_context
                    or not companion.is_file()
                    or companion.resolve() == harness.resolve()
                ):
                    continue
                value = _safe_relative_source(
                    companion.resolve().relative_to(source_root).as_posix()
                )
                if value and value not in support:
                    support.add(value)
                    pending.append(companion)
    return sorted(support), sorted(include_directories)


def _is_harness_support_path(relative: str) -> bool:
    return bool(
        {part.casefold() for part in Path(relative).parts[:-1]}
        & HARNESS_SUPPORT_DIRECTORY_NAMES
    )


def _project_header_index(source_root: Path) -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = {}
    indexed = 0
    for path in source_root.rglob("*"):
        if indexed >= 10_000:
            break
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.casefold() not in HEADER_SUFFIXES:
            continue
        index.setdefault(path.name, []).append(path.resolve())
        indexed += 1
    return index


def _resolve_project_header(
    source_root: Path,
    including_dir: Path,
    include: str,
    header_index: dict[str, list[Path]] | None,
) -> Path | None:
    safe_include = _safe_relative_source(include)
    if not safe_include:
        return None
    direct = (including_dir / safe_include).resolve()
    try:
        direct.relative_to(source_root)
    except ValueError:
        return None
    if direct.is_file():
        return direct
    root_relative = (source_root / safe_include).resolve()
    if root_relative.is_file():
        return root_relative
    index = header_index or {}
    matches = index.get(Path(safe_include).name, [])
    return matches[0] if len(matches) == 1 else None


def _candidate_harness_language(candidate: dict[str, Any], origin: str) -> str:
    if origin.startswith("existing:") and Path(
        str(candidate.get("file") or "")
    ).suffix.casefold() == ".c":
        return "c"
    return "c++"


def _build_script(
    build_system: str,
    harness_include_dir: str = "",
    support_sources: list[str] | tuple[str, ...] = (),
    harness_language: str = "c++",
    support_include_dirs: list[str] | tuple[str, ...] = (),
    source_dependencies: list[str] | tuple[str, ...] = (),
    *,
    allow_header_only_cmake: bool = False,
) -> str:
    prelude = """#!/usr/bin/env bash
set -euo pipefail
export CC CXX CFLAGS CXXFLAGS LIB_FUZZING_ENGINE OUT WORK
reuse_build="${FUZZ_REUSE_BUILD:-0}"
if [[ "$reuse_build" != "1" ]]; then
  rm -rf "$WORK/build"
fi
mkdir -p "$WORK/build" "$OUT"
"""
    dependency_build = ""
    for name in sorted(
        dependency
        for dependency in set(source_dependencies)
        if dependency in CMAKE_SOURCE_DEPENDENCIES
        and CMAKE_SOURCE_DEPENDENCIES[dependency].get("build_separately", True)
    ):
        dependency_build += f"""rm -rf "$WORK/dependency-{name}"
cmake -S "/opt/fuzz-dependencies/{name}" -B "$WORK/dependency-{name}" -G Ninja \\
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_STANDARD=17 \\
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \\
  -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \\
  -DCMAKE_INSTALL_PREFIX="$WORK/dependencies" \\
  -DBUILD_SHARED_LIBS=OFF -DABSL_BUILD_TESTING=OFF
cmake --build "$WORK/dependency-{name}" --parallel "$(nproc)"
cmake --install "$WORK/dependency-{name}"
"""
    if dependency_build:
        dependency_build = (
            'if [[ "$reuse_build" != "1" ]]; then\n'
            '  rm -rf "$WORK/dependencies"\n'
            '  mkdir -p "$WORK/dependencies"\n'
            + dependency_build
            + "fi\n"
            + 'export CMAKE_PREFIX_PATH="$WORK/dependencies"\n'
        )
    cmake_source_args = ""
    for name in sorted(set(source_dependencies)):
        metadata = CMAKE_SOURCE_DEPENDENCIES.get(name) or {}
        variable = str(metadata.get("cmake_source_variable") or "")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", variable):
            continue
        cmake_source_args += (
            f'cmake_shared_args+=("-D{variable}='
            f'/opt/fuzz-dependencies/{name}")\n'
        )
    builds = {
        "cmake": """cmake_shared_args=(-DBUILD_SHARED_LIBS=OFF)
while IFS= read -r option; do
  cmake_shared_args+=("-D${option}=OFF")
done < <(
  grep -rhoEi 'option[(][A-Za-z_][A-Za-z0-9_]*BUILD_SHARED[A-Za-z0-9_]*' \
    CMakeLists.txt cmake 2>/dev/null | sed -E 's/^[Oo][Pp][Tt][Ii][Oo][Nn][(]//' | sort -u
)
while IFS= read -r option; do
  cmake_shared_args+=("-D${option}=OFF")
done < <(
  grep -rhoEi 'option[(][A-Za-z_][A-Za-z0-9_]*' \
    CMakeLists.txt cmake tools 2>/dev/null | sed -E 's/^[Oo][Pp][Tt][Ii][Oo][Nn][(]//' | \
    grep -E '(^|_)(BUILD_(TESTS?|TESTING|BENCHMARKS?|EXAMPLES?|TOOLS?|CLI|DOCS?|PYTHON_EXT(_TESTS)?|WASM|ALL_MICROKERNELS)|ENABLE_KLEIDIAI|ENABLE_TESTING)$' | \
    sort -u
)
cmake_build_type=RelWithDebInfo
if grep -RqiE 'CMAKE_BUILD_TYPE must be either.*debug.*release|VALID_BUILD_TYPE.*debug.*release' \
  CMakeLists.txt cmake 2>/dev/null; then
  cmake_build_type=release
fi
cmake -S . -B "$WORK/build" -G Ninja \
  -DCMAKE_BUILD_TYPE="$cmake_build_type" "${cmake_shared_args[@]}" \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS"
cmake --build "$WORK/build" --parallel "$(nproc)"
""",
        "meson": """CC="$CC" CXX="$CXX" meson setup "$WORK/build" . \
  --default-library=static --buildtype=debugoptimized
mapfile -d '' archive_targets < <(python3 - "$WORK/build" <<'PY'
import json
import os
import sys
from pathlib import Path

build = Path(sys.argv[1]).resolve()
targets = json.loads((build / 'meson-info/intro-targets.json').read_text())
for target in targets:
    if target.get('type') != 'static library':
        continue
    filenames = target.get('filename') or []
    if isinstance(filenames, str):
        filenames = [filenames]
    for filename in filenames:
        path = Path(filename)
        path = (path if path.is_absolute() else build / path).resolve()
        try:
            relative = path.relative_to(build)
        except ValueError:
            continue
        if path.suffix == '.a':
            sys.stdout.buffer.write(os.fsencode(str(relative)) + bytes([0]))
PY
)
if (( ${#archive_targets[@]} == 0 )); then
  echo 'generic integration found no Meson static library targets' >&2
  exit 1
fi
ninja -C "$WORK/build" "${archive_targets[@]}"
""",
        "autotools": """autoreconf -fi
CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" \\
  ./configure --disable-shared --enable-static
make -j"$(nproc)"
find . -type f -name '*.a' -exec cp -n {} "$WORK/build/" \\;
""",
        "cargo": """RUSTFLAGS="${RUSTFLAGS:-} -C debuginfo=2" cargo build --release --lib
find target/release -maxdepth 2 -type f -name '*.a' -exec cp -n {} "$WORK/build/" \\;
""",
    }
    include_directories = {harness_include_dir} if harness_include_dir else set()
    include_directories.update(
        Path(value).parent.as_posix()
        for value in support_sources
        if _safe_relative_source(str(value)) and Path(value).parent.as_posix() != "."
    )
    include_directories.update(
        value
        for raw_value in support_include_dirs
        if (value := _safe_relative_source(str(raw_value)))
        and Path(value).as_posix() != "."
    )
    harness_include = "".join(
        f' "-I$SRC/project/{value}"' for value in sorted(include_directories)
    )
    support_compile_lines: list[str] = []
    for index, raw_source in enumerate(support_sources):
        support_source = _safe_relative_source(str(raw_source))
        if (
            not support_source
            or Path(support_source).suffix.casefold() not in SOURCE_SUFFIXES
        ):
            continue
        is_c = Path(support_source).suffix.casefold() == ".c"
        compiler = "$CC" if is_c else "$CXX"
        flags = "$CFLAGS" if is_c else "$CXXFLAGS"
        support_compile_lines.append(
            f'"{compiler}" {flags} "${{include_flags[@]}}" -c '
            f'"$SRC/project/{support_source}" '
            f'-o "$WORK/harness-support-{index}.o"\n'
            f'support_objects+=("$WORK/harness-support-{index}.o")'
        )
    harness_compiler = "$CC" if harness_language == "c" else "$CXX"
    harness_flags = (
        "$CFLAGS -x c" if harness_language == "c" else "$CXXFLAGS -std=c++17"
    )
    support_compile = "\n".join(support_compile_lines)
    external_libraries = (
        """meson_external_libs=()
if pkg-config --exists jsoncpp; then
  read -r -a meson_external_libs <<< "$(pkg-config --libs jsoncpp)"
fi
"""
        if build_system == "meson" else ""
    )
    external_link_flags = ' "${meson_external_libs[@]}"' if build_system == "meson" else ""
    link = """mapfile -d '' archives < <(find "$WORK/build" -type f -name '*.a' -print0)
mapfile -d '' dependency_archives < <(
  find "$WORK/dependencies" -type f -name '*.a' -print0 2>/dev/null
)
include_flags=("-I$SRC/project"__HARNESS_INCLUDE__)
if [[ -f "$WORK/build/build.ninja" ]]; then
  while IFS= read -r flag; do
    case "$flag" in
      -I*) include_option=-I; include_path="${flag#-I}" ;;
      -isystem*) include_option=-isystem; include_path="${flag#-isystem}" ;;
      -iquote*) include_option=-iquote; include_path="${flag#-iquote}" ;;
      *) continue ;;
    esac
    [[ -n "$include_path" ]] || continue
    if [[ "$include_path" != /* ]]; then
      include_path="$WORK/build/$include_path"
    fi
    include_flags+=("$include_option$include_path")
  done < <(
    ninja -C "$WORK/build" -t commands 2>/dev/null |
      awk '{for (i=1; i<=NF; i++) {
        if (($i == "-I" || $i == "-isystem" || $i == "-iquote") && i < NF) {
          option=$i; i++; print option $i;
        } else if ($i ~ /^-I.+/ || $i ~ /^-isystem.+/ || $i ~ /^-iquote.+/) {
          print $i;
        }
      }}' | sort -u
  )
fi
if (( ${#include_flags[@]} == 1 )); then
  while IFS= read -r directory; do
    include_flags+=("-I$directory")
  done < <(
    find "$SRC/project" "$WORK/build" -regextype posix-extended -type d \\
      -regex '.*/(include|inc)' -print 2>/dev/null | sort -u | head -n 100
  )
fi
include_flags+=("-I$WORK/build")
if (( ${#archives[@]} == 0 && __REQUIRE_STATIC_ARCHIVES__ == 1 )); then
  echo 'generic integration found no static libraries' >&2
  exit 1
fi
support_objects=()
__SUPPORT_COMPILE__
"__HARNESS_COMPILER__" __HARNESS_FLAGS__ "${include_flags[@]}" \\
  -c "$SRC/generic_harness.cc" -o "$WORK/generic_harness.o"
"$CXX" $CXXFLAGS "$WORK/generic_harness.o" "${support_objects[@]}" \\
  -Wl,--start-group "${archives[@]}" "${dependency_archives[@]}" -Wl,--end-group \\
  __EXTERNAL_LIBS__ $LIB_FUZZING_ENGINE ${LIBS:-} -o "$OUT/generic_fuzzer"
"""
    link = link.replace(
        "__REQUIRE_STATIC_ARCHIVES__",
        "0" if build_system == "cmake" and allow_header_only_cmake else "1",
    )
    link = link.replace("__EXTERNAL_LIBS__", external_link_flags)
    link = link.replace("__HARNESS_INCLUDE__", harness_include)
    link = link.replace("__SUPPORT_COMPILE__", support_compile)
    link = link.replace("__HARNESS_COMPILER__", harness_compiler)
    link = link.replace("__HARNESS_FLAGS__", harness_flags)
    build = builds[build_system]
    if build_system == "cmake" and cmake_source_args:
        build = build.replace(
            "cmake_shared_args=(-DBUILD_SHARED_LIBS=OFF)\n",
            "cmake_shared_args=(-DBUILD_SHARED_LIBS=OFF)\n" + cmake_source_args,
        )
    return prelude + dependency_build + build + external_libraries + link


def _read_optional_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PipelineError(f"could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PipelineError(f"expected an object in {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
