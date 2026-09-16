from __future__ import annotations

import hashlib
import json
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
    "bzip2": ("libbz2-dev",),
    "expat": ("libexpat1-dev",),
    "libxml2": ("libxml2-dev",),
    "openssl": ("libssl-dev",),
    "protobuf": ("libprotobuf-dev", "protobuf-compiler"),
    "zlib": ("zlib1g-dev",),
}
CMAKE_SOURCE_DEPENDENCIES = {
    "absl": {
        "url": "https://github.com/abseil/abseil-cpp.git",
        "commit": "d38452e1ee03523a208362186fd42248ff2609f6",
    },
}


def detect_build_system(source: Path) -> str:
    for name, markers in BUILD_SYSTEM_MARKERS:
        if any((source / marker).is_file() for marker in markers):
            return name
    raise PipelineError("no supported CMake, Meson, Autotools, or Cargo build was detected")


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
) -> dict[str, Any]:
    progress = progress or (lambda _: None)
    build_system = detect_build_system(source)
    system_dependencies = _detect_system_dependencies(source, build_system)
    source_dependencies = _detect_source_dependencies(source, build_system)
    project_dir.mkdir(parents=True, exist_ok=False)
    harness, origin, usage, candidate = _obtain_harness(
        job_dir, source, project_name, pipeline, progress
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
) -> dict[str, Any]:
    record_path = job_dir / "artifacts" / "generic-integration.json"
    record = _read_json(record_path)
    candidate = record.get("candidate") or {}
    harness_origin = str(record.get("harness_origin", ""))
    if harness_origin.startswith("existing:"):
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
        record["support_sources"] = support_sources
        record["support_include_dirs"] = support_include_dirs
        record.setdefault("repair_attempts", []).append(item)
        _write_json(record_path, record)
        return item
    if not candidate.get("file"):
        candidate = _select_public_candidate(source)
    context = source_context(source, candidate, radius=140)
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
    response, usage = invoke_oss_fuzz_gen_adapter(pipeline, prompt, output)
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
    candidate = _select_public_candidate(source)
    context = source_context(source, candidate, radius=140)
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
    response, usage = invoke_oss_fuzz_gen_adapter(pipeline, prompt, output)
    code = extract_harness_code(response)
    validate_generated_harness(code, candidate)
    return code, "codex_oss_fuzz_gen_adapter", usage, candidate


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


def _select_public_candidate(source: Path) -> dict[str, Any]:
    prototype = re.compile(
        r"^\s*(?:extern\s+\"C\"\s+)?(?:[A-Za-z_][\w:<>,*&\s]+)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_:]*)\s*\([^;{}]*\)\s*;"
    )
    rejected = {"main", "malloc", "free", "operator", "if", "for", "while"}
    for path in sorted(source.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.suffix.casefold() not in HEADER_SUFFIXES:
            continue
        try:
            if path.stat().st_size > 300_000:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            match = prototype.match(line)
            if not match or match.group("name").split("::")[-1] in rejected:
                continue
            return {
                "id": hashlib.sha256(f"{path}:{number}".encode()).hexdigest()[:16],
                "file": path.relative_to(source).as_posix(),
                "local_symbol_line": number,
                "signature": line.strip()[:1000],
            }
    raise PipelineError("no existing harness or public function prototype was found")


def _detect_system_dependencies(source: Path, build_system: str) -> list[str]:
    packages = _declared_cmake_packages(source) if build_system == "cmake" else set()
    dependencies: set[str] = set()
    for package in packages:
        dependencies.update(CMAKE_SYSTEM_DEPENDENCIES.get(package, ()))
    return sorted(dependencies)


def _detect_source_dependencies(source: Path, build_system: str) -> list[str]:
    packages = _declared_cmake_packages(source) if build_system == "cmake" else set()
    return sorted(packages & CMAKE_SOURCE_DEPENDENCIES.keys())


def _declared_cmake_packages(source: Path) -> set[str]:
    files: list[Path] = []
    root = source / "CMakeLists.txt"
    if root.is_file() and not root.is_symlink():
        files.append(root)
    cmake_dir = source / "cmake"
    if cmake_dir.is_dir() and not cmake_dir.is_symlink():
        files.extend(
            path
            for path in sorted(cmake_dir.rglob("*.cmake"))
            if path.is_file() and not path.is_symlink()
        )
    packages: set[str] = set()
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
        for match in re.finditer(
            r"\bfind_package\s*\(\s*([A-Za-z0-9_+.-]+)",
            text,
            re.IGNORECASE,
        ):
            packages.add(match.group(1).casefold())
    return packages


def _dockerfile(
    build_system: str,
    native_base_image: str | None = None,
    system_dependencies: list[str] | tuple[str, ...] = (),
    source_dependencies: list[str] | tuple[str, ...] = (),
) -> str:
    packages = {
        "cmake": "cmake ninja-build pkg-config",
        "meson": "meson ninja-build pkg-config",
        "autotools": "autoconf automake libtool make pkg-config",
        "cargo": "cargo rustc pkg-config",
    }[build_system]
    allowed_dependencies = sorted(
        {
            dependency
            for dependency in system_dependencies
            if dependency
            in {
                package
                for packages in CMAKE_SYSTEM_DEPENDENCIES.values()
                for package in packages
            }
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
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates clang lld llvm file libclang-rt-dev libc++-dev libc++abi-dev \
    build-essential {packages}{dependency_packages}{source_package} \
    && rm -rf /var/lib/apt/lists/*
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
) -> str:
    prelude = """#!/usr/bin/env bash
set -euo pipefail
export CC CXX CFLAGS CXXFLAGS LIB_FUZZING_ENGINE OUT WORK
rm -rf "$WORK/build"
mkdir -p "$WORK/build" "$OUT"
"""
    dependency_build = ""
    for name in sorted(
        dependency
        for dependency in set(source_dependencies)
        if dependency in CMAKE_SOURCE_DEPENDENCIES
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
            'rm -rf "$WORK/dependencies"\nmkdir -p "$WORK/dependencies"\n'
            + dependency_build
            + 'export CMAKE_PREFIX_PATH="$WORK/dependencies"\n'
        )
    builds = {
        "cmake": """cmake_shared_args=(-DBUILD_SHARED_LIBS=OFF)
while IFS= read -r option; do
  cmake_shared_args+=("-D${option}=OFF")
done < <(
  grep -rhoE 'option[(][A-Za-z_][A-Za-z0-9_]*BUILD_SHARED[A-Za-z0-9_]*' \
    CMakeLists.txt cmake 2>/dev/null | sed 's/^option(//' | sort -u
)
cmake -S . -B "$WORK/build" -G Ninja \\
  -DCMAKE_BUILD_TYPE=RelWithDebInfo "${cmake_shared_args[@]}" \\
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \\
  -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS"
cmake --build "$WORK/build" --parallel "$(nproc)"
""",
        "meson": """CC="$CC" CXX="$CXX" meson setup "$WORK/build" . \\
  --default-library=static --buildtype=debugoptimized
meson compile -C "$WORK/build"
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
    link = """mapfile -d '' archives < <(find "$WORK/build" -type f -name '*.a' -print0)
mapfile -d '' dependency_archives < <(
  find "$WORK/dependencies" -type f -name '*.a' -print0 2>/dev/null
)
include_flags=("-I$SRC/project"__HARNESS_INCLUDE__)
if [[ -f "$WORK/build/build.ninja" ]]; then
  while IFS= read -r flag; do
    include_flags+=("$flag")
  done < <(
    ninja -C "$WORK/build" -t commands 2>/dev/null |
      awk '{for (i=1; i<=NF; i++) {
        if ($i ~ /^-I.+/) print $i;
        else if (($i == "-isystem" || $i == "-iquote") && i < NF) print $i $(i+1);
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
if (( ${#archives[@]} == 0 )); then
  echo 'generic integration found no static libraries' >&2
  exit 1
fi
support_objects=()
__SUPPORT_COMPILE__
"__HARNESS_COMPILER__" __HARNESS_FLAGS__ "${include_flags[@]}" \\
  -c "$SRC/generic_harness.cc" -o "$WORK/generic_harness.o"
"$CXX" $CXXFLAGS "$WORK/generic_harness.o" "${support_objects[@]}" \\
  -Wl,--start-group "${archives[@]}" "${dependency_archives[@]}" -Wl,--end-group \\
  $LIB_FUZZING_ENGINE ${LIBS:-} -o "$OUT/generic_fuzzer"
"""
    link = link.replace("__HARNESS_INCLUDE__", harness_include)
    link = link.replace("__SUPPORT_COMPILE__", support_compile)
    link = link.replace("__HARNESS_COMPILER__", harness_compiler)
    link = link.replace("__HARNESS_FLAGS__", harness_flags)
    return prelude + dependency_build + builds[build_system] + link


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
