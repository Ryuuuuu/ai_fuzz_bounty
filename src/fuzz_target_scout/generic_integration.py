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
    project_dir.mkdir(parents=True, exist_ok=False)
    harness, origin, usage, candidate = _obtain_harness(
        job_dir, source, project_name, pipeline, progress
    )
    harness_path = project_dir / "generic_harness.cc"
    harness_path.write_text(harness, encoding="utf-8")
    harness_path.chmod(0o644)
    (project_dir / "Dockerfile").write_text(
        _dockerfile(build_system, base_image if native else None),
        encoding="utf-8",
    )
    support_sources = _candidate_support_sources(source, candidate)
    harness_language = _candidate_harness_language(candidate, origin)
    build_script = _build_script(
        build_system,
        _candidate_include_dir(candidate),
        support_sources,
        harness_language,
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
        support_sources = sorted(
            set(record.get("support_sources") or [])
            | set(_candidate_support_sources(source, candidate))
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
    existing = _find_existing_harness(source)
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


def _find_existing_harness(source: Path) -> Path | None:
    for path in sorted(source.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.suffix.casefold() not in SOURCE_SUFFIXES:
            continue
        try:
            if path.stat().st_size > 500_000:
                continue
            if "LLVMFuzzerTestOneInput" in path.read_text(encoding="utf-8", errors="replace"):
                return path
        except OSError:
            continue
    return None


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


def _dockerfile(build_system: str, native_base_image: str | None = None) -> str:
    packages = {
        "cmake": "cmake ninja-build pkg-config",
        "meson": "meson ninja-build pkg-config",
        "autotools": "autoconf automake libtool make pkg-config",
        "cargo": "cargo rustc pkg-config",
    }[build_system]
    if native_base_image is None:
        return f"""FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    {packages} \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 build.sh $SRC/build.sh
COPY --chmod=0644 generic_harness.cc $SRC/generic_harness.cc
WORKDIR $SRC/project
"""
    if not re.fullmatch(r"[A-Za-z0-9./:_-]{3,200}", native_base_image):
        raise PipelineError("native builder image reference is invalid")
    return f"""FROM {native_base_image}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates clang lld llvm file libclang-rt-dev libc++-dev libc++abi-dev \
    build-essential {packages} \
    && rm -rf /var/lib/apt/lists/*
ENV SRC=/src WORK=/work OUT=/out \
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
    relative = _safe_relative_source(str(candidate.get("file") or ""))
    if not relative:
        return []
    harness = source / relative
    try:
        text = harness.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    support: set[str] = set()
    for include in re.findall(r'^\s*#\s*include\s*"([^"\n]+)"', text, re.MULTILINE):
        header = (harness.parent / include).resolve()
        try:
            header.relative_to(source.resolve())
        except ValueError:
            continue
        for suffix in SOURCE_SUFFIXES:
            companion = header.with_suffix(suffix)
            if not companion.is_file() or companion == harness:
                continue
            value = _safe_relative_source(companion.relative_to(source).as_posix())
            if value:
                support.add(value)
    return sorted(support)


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
) -> str:
    prelude = """#!/usr/bin/env bash
set -euo pipefail
export CC CXX CFLAGS CXXFLAGS LIB_FUZZING_ENGINE OUT WORK
rm -rf "$WORK/build"
mkdir -p "$WORK/build" "$OUT"
"""
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
    harness_include = (
        f' "-I$SRC/project/{harness_include_dir}"'
        if harness_include_dir
        else ""
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
  -Wl,--start-group "${archives[@]}" -Wl,--end-group \\
  $LIB_FUZZING_ENGINE ${LIBS:-} -o "$OUT/generic_fuzzer"
"""
    link = link.replace("__HARNESS_INCLUDE__", harness_include)
    link = link.replace("__SUPPORT_COMPILE__", support_compile)
    link = link.replace("__HARNESS_COMPILER__", harness_compiler)
    link = link.replace("__HARNESS_FLAGS__", harness_flags)
    return prelude + builds[build_system] + link


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
