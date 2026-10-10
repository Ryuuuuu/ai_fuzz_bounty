from __future__ import annotations

import hashlib
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .architecture import normalize_architecture, resolve_host_architecture
from .models import RepoSnapshot


DOCKERFILE = """FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends clang cmake ninja-build build-essential pkg-config python3 ca-certificates libgtest-dev libgmock-dev libboost-dev libboost-filesystem-dev libboost-iostreams-dev libboost-program-options-dev libboost-regex-dev libboost-thread-dev libcli11-dev libfmt-dev libjsoncpp-dev libre2-dev libgflags-dev libgoogle-glog-dev libssl-dev zlib1g-dev default-jdk-headless && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/default-java
"""

# These scripts run inside the networkless container. The CMake File API ties
# the selected CTest executable to a target with a real C/C++ compile command.
SELECT_NATIVE_TEST = r"""import json
import re
import sys
from pathlib import Path

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++"}


def resolved(base, raw):
    path = Path(raw)
    return (path if path.is_absolute() else base / path).resolve()


def within(root, path):
    try:
        path.relative_to(root.resolve())
        return True
    except ValueError:
        return False


def candidate_targets(targets):
    # Choose a small set of buildable test-like C/C++ executables.
    ranked = []
    seen = set()
    for _artifact, name in targets:
        # Each name becomes one quoted cmake --build argument in the shell.
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*", name) or name in seen:
            continue
        lower = name.casefold()
        if not re.search(r"test|unit|smoke|check|spec", lower):
            continue
        seen.add(name)
        priority = 0 if "test" in lower else 1 if "unit" in lower else 2
        ranked.append((priority, len(name), name))
    return [name for _priority, _length, name in sorted(ranked)[:3]]


def select_native_test(
    build, source, tests_path, *, candidates=False, standalone_target=None
):
    commands = json.loads((build / "compile_commands.json").read_text())
    compiled = {
        resolved(Path(item["directory"]), item["file"])
        for item in commands
        if isinstance(item, dict)
        and item.get("directory")
        and item.get("file")
        and Path(item["file"]).suffix.casefold() in SOURCE_SUFFIXES
    }
    if not compiled:
        raise ValueError("no C/C++ compile commands")

    reply = build / ".cmake/api/v1/reply"
    indexes = sorted(reply.glob("index-*.json"))
    if not indexes:
        raise ValueError("CMake File API reply is missing")
    index = json.loads(indexes[-1].read_text())
    model_ref = (index.get("reply") or {}).get("codemodel-v2")
    if not model_ref:
        raise ValueError("CMake codemodel is missing")
    model = json.loads((reply / model_ref["jsonFile"]).read_text())
    targets = []
    for configuration in model.get("configurations", []):
        for reference in configuration.get("targets", []):
            target = json.loads((reply / reference["jsonFile"]).read_text())
            if target.get("type") != "EXECUTABLE":
                continue
            c_groups = {
                number
                for number, group in enumerate(target.get("compileGroups", []))
                if group.get("language") in {"C", "CXX"}
            }
            target_sources = set()
            for item in target.get("sources", []):
                if item.get("compileGroupIndex") not in c_groups:
                    continue
                raw = item.get("path")
                if raw:
                    target_sources.add(resolved(source, raw))
                    target_sources.add(resolved(build, raw))
            if not target_sources.intersection(compiled):
                continue
            for artifact in target.get("artifacts", []):
                path = resolved(build, artifact.get("path", ""))
                if within(build, path):
                    targets.append((path, reference["name"]))

    if candidates:
        return candidate_targets(targets)

    if standalone_target is not None:
        if standalone_target not in candidate_targets(targets):
            raise ValueError("standalone target is not a C/C++ test candidate")
        for artifact, target_name in targets:
            if target_name == standalone_target and artifact.is_file():
                return {
                    "artifact": str(artifact),
                    "target": target_name,
                    "kind": "standalone",
                }
        raise ValueError("built standalone test executable is missing")

    tests = json.loads(tests_path.read_text()).get("tests", [])
    for number, test in enumerate(tests, 1):
        command = test.get("command") or []
        if not command or not isinstance(command[0], str):
            continue
        executable = resolved(build, command[0])
        if not within(build, executable):
            continue
        for artifact, target_name in targets:
            if artifact == executable:
                return {
                    "artifact": str(artifact),
                    "target": target_name,
                    "test_index": number,
                    "test_name": test.get("name", ""),
                }
    raise ValueError("no CTest executable backed by a C/C++ CMake target")


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--candidates"]:
            names = select_native_test(
                Path(sys.argv[2]), Path(sys.argv[3]), None, candidates=True
            )
            if names:
                print("\n".join(names))
        elif sys.argv[1:2] == ["--standalone"]:
            selected = select_native_test(
                Path(sys.argv[2]), Path(sys.argv[3]), None,
                standalone_target=sys.argv[5],
            )
            Path(sys.argv[4]).write_text(json.dumps(selected))
        else:
            selected = select_native_test(
                Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
            )
            Path(sys.argv[4]).write_text(json.dumps(selected))
    except (OSError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise SystemExit(f"native test selection failed: {exc}")
"""

VERIFY_NATIVE_TEST = r"""import json
import os
import re
import subprocess
import sys
from pathlib import Path


def first_gtest_case(output):
    suite = None
    for raw in output.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        if not line[0].isspace():
            name = line[:-1] if line.endswith(".") else ""
            suite = name if re.fullmatch(r"[A-Za-z0-9_./]+", name) else None
            continue
        case = line.strip()
        if suite and re.fullmatch(r"[A-Za-z0-9_./]+", case):
            parts = (suite + "." + case).replace("/", ".").split(".")
            if not any(part.startswith("DISABLED_") for part in parts):
                return suite + "." + case
    return None


def run_standalone_test(artifact, build):
    listing = subprocess.run(
        [str(artifact), "--gtest_list_tests"], cwd=build,
        capture_output=True, text=True, timeout=8, check=False,
    )
    case = first_gtest_case(listing.stdout) if listing.returncode == 0 else None
    if case:
        result = subprocess.run(
            [str(artifact), f"--gtest_filter={case}", "--gtest_color=no"],
            cwd=build, capture_output=True, text=True, timeout=30, check=False,
        )
        output = result.stdout + result.stderr
        print(output[-8192:])
        ran = re.search(
            r"^\[\s*RUN\s*\]\s+" + re.escape(case) + r"$",
            output, re.MULTILINE,
        )
        passed_case = re.search(
            r"^\[\s*OK\s*\]\s+" + re.escape(case) + r"\s+\(",
            output, re.MULTILINE,
        )
        passed_count = re.search(
            r"^\[\s*PASSED\s*\]\s+1 test\.$", output, re.MULTILINE,
        )
        if result.returncode != 0 or not (ran and passed_case and passed_count):
            raise ValueError("standalone GoogleTest did not pass one test")
        return
    if listing.returncode == 0 and re.search(
        r"(?m)^[A-Za-z0-9_./]+\.$", listing.stdout
    ):
        raise ValueError("standalone GoogleTest has no enabled test")
    result = subprocess.run(
        [str(artifact)], cwd=build,
        capture_output=True, text=True, timeout=30, check=False,
    )
    output = result.stdout + result.stderr
    print(output[-8192:])
    if result.returncode != 0 or not output.strip():
        raise ValueError("standalone native test did not provide a passing smoke")


def verify_native_test(build, selection_path):
    selection = json.loads(selection_path.read_text())
    artifact = Path(selection["artifact"]).resolve(strict=True)
    try:
        artifact.relative_to(build.resolve())
    except ValueError:
        raise ValueError("test executable escapes build directory")
    if not artifact.is_file() or not os.access(artifact, os.X_OK):
        raise ValueError("test executable is missing")
    with artifact.open("rb") as binary:
        header = binary.read(20)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise ValueError("test executable is not ELF")
    endian = {1: "little", 2: "big"}.get(header[5])
    if endian is None or int.from_bytes(header[18:20], endian) != 183:
        raise ValueError("test executable is not AArch64")
    if selection.get("kind") == "standalone":
        run_standalone_test(artifact, build)
        return
    if selection.get("kind") not in (None, "ctest"):
        raise ValueError("unknown native test selection kind")
    number = int(selection["test_index"])
    result = subprocess.run(
        [
            "ctest", "--test-dir", str(build), "--output-on-failure",
            "-I", f"{number},{number}", "--timeout", "30",
        ],
        capture_output=True, text=True, timeout=40, check=False,
    )
    output = result.stdout + result.stderr
    print(output[-8192:])
    if result.returncode != 0 or not re.search(
        r"^100% tests passed, 0 tests failed out of 1$", output, re.MULTILINE
    ):
        raise ValueError("selected native CTest did not pass")


if __name__ == "__main__":
    try:
        verify_native_test(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, KeyError, TypeError, ValueError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(f"native test smoke failed: {exc}")
"""

SELECT_CMAKE_NONTEST_OPTIONS = r"""import re
import sys
from pathlib import Path

# Only declared, conventional benchmark/example switches may be changed.
# The names are validated before they become individual quoted shell arguments.
DECLARATION = re.compile(
    r'(?im)^[ \t]*(?:option|cmake_dependent_option)[ \t]*\([ \t]*'
    r'([A-Za-z][A-Za-z0-9_]*)(?=[ \t\r\n)])'
)
NONTEST_OPTION = re.compile(
    r'(?:[A-Z][A-Z0-9]*_)*(?:BUILD|ENABLE|WITH)_(?:BENCHMARKS?|EXAMPLES?)'
)

source = Path(sys.argv[1]) / 'CMakeLists.txt'
if source.stat().st_size > 2 * 1024 * 1024:
    raise SystemExit('CMake option scan exceeded size limit')
names = sorted(set(DECLARATION.findall(source.read_text(errors='replace'))))
for name in [n for n in names if len(n) <= 64 and NONTEST_OPTION.fullmatch(n)][:24]:
    print(f'-D{name}=OFF')
"""

BUILD_AND_SMOKE = (
    """stage=configure
trap 'code=$?; if [ "$code" -ne 0 ]; then printf "FTS_ARM_PREFLIGHT_FAILED_STAGE:%s:%s\\n" "$stage" "$code" >&2; fi' EXIT
printf 'FTS_ARM_PREFLIGHT_STAGE:%s\\n' "$stage"
mkdir /work/src
cp -a /src/. /work/src/
mkdir -p /work/build/.cmake/api/v1/query
: > /work/build/.cmake/api/v1/query/codemodel-v2
cat > /work/select_cmake_nontest_options.py <<'PY'
"""
    + SELECT_CMAKE_NONTEST_OPTIONS
    + """PY
python3 /work/select_cmake_nontest_options.py /work/src > /work/nontest-options.txt
set --
# Use the GoogleTest sources supplied by the base image when available.
# Other CMake projects can ignore this cache entry.
if [ -f /usr/src/googletest/CMakeLists.txt ] &&
   [ -f /usr/src/googletest/googletest/CMakeLists.txt ] &&
   [ -f /usr/src/googletest/googlemock/CMakeLists.txt ]; then
  set -- "$@" -DGOOGLETEST_PATH=/usr/src/googletest
  set -- "$@" -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=/usr/src/googletest
fi
while IFS= read -r option; do
  set -- "$@" "$option"
done < /work/nontest-options.txt
cmake -S /work/src -B /work/build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_TESTING=ON -DFETCHCONTENT_FULLY_DISCONNECTED=ON "$@"
stage=select_native_test
printf 'FTS_ARM_PREFLIGHT_STAGE:%s\\n' "$stage"
ctest --test-dir /work/build --show-only=json-v1 > /work/tests.json
cat > /work/select_native_test.py <<'PY'
"""
    + SELECT_NATIVE_TEST
    + """PY
if ! python3 /work/select_native_test.py /work/build /work/src /work/tests.json /work/selection.json; then
  # Some CTest entries, including gtest_discover_tests, gain a command only
  # after their executable has been built. Probe at most three likely targets.
  python3 /work/select_native_test.py --candidates /work/build /work/src > /work/candidates.txt
  if [ ! -s /work/candidates.txt ]; then
    printf 'native test selection failed: no CTest executable backed by a C/C++ CMake target\n' >&2
    exit 1
  fi
  built_any=0
  while IFS= read -r candidate; do
    stage=build
    printf 'FTS_ARM_PREFLIGHT_STAGE:%s\n' "$stage"
    if cmake --build /work/build --target "$candidate" --parallel 2; then
      built_any=1
      stage=select_native_test
      printf 'FTS_ARM_PREFLIGHT_STAGE:%s\n' "$stage"
      ctest --test-dir /work/build --show-only=json-v1 > /work/tests.json
      if python3 /work/select_native_test.py /work/build /work/src /work/tests.json /work/selection.json; then
        break
      fi
      # A compiled C/C++ test executable can be runnable even when CTest has
      # no entry. Verify the exact built target directly in the smoke stage.
      if python3 /work/select_native_test.py --standalone /work/build /work/src /work/selection.json "$candidate"; then
        break
      fi
    fi
  done < /work/candidates.txt
fi
if [ ! -s /work/selection.json ]; then
  if [ "$built_any" -eq 0 ]; then
    stage=build
    printf 'native test candidate builds failed\n' >&2
  else
    stage=select_native_test
    printf 'native test selection failed: no CTest executable backed by a C/C++ CMake target\n' >&2
  fi
  exit 1
fi
target=$(python3 -c 'import json; print(json.load(open("/work/selection.json"))["target"])')
stage=build
printf 'FTS_ARM_PREFLIGHT_STAGE:%s\\n' "$stage"
cmake --build /work/build --target "$target" --parallel 2
stage=smoke
printf 'FTS_ARM_PREFLIGHT_STAGE:%s\\n' "$stage"
cat > /work/verify_native_test.py <<'PY'
"""
    + VERIFY_NATIVE_TEST
    + """PY
python3 /work/verify_native_test.py /work/build /work/selection.json
printf 'FTS_ARM_PREFLIGHT_OK\\n'
"""
)

PREFLIGHT_VERSION = hashlib.sha256(
    (DOCKERFILE + "\n" + BUILD_AND_SMOKE).encode("utf-8")
).hexdigest()[:16]
IMAGE_TAG = f"fts-arm-preflight:{PREFLIGHT_VERSION}"
MESON_DOCKERFILE = """FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends clang meson ninja-build build-essential pkg-config python3 git ca-certificates libjsoncpp-dev libgtest-dev libgmock-dev && rm -rf /var/lib/apt/lists/*
"""

# Meson introspection binds the selected test command to a C/C++ executable
# target and a real compile command. A script or unrelated prebuilt ELF cannot
# satisfy the native proof.
SELECT_MESON_NATIVE_TEST = r"""import json
import re
import sys
from pathlib import Path

SOURCE_SUFFIXES = {'.c', '.cc', '.cpp', '.cxx', '.c++'}


def resolved(base, raw):
    path = Path(raw)
    return (path if path.is_absolute() else base / path).resolve()


def within(root, path):
    try:
        path.relative_to(root.resolve())
        return True
    except ValueError:
        return False


def select_meson_native_test(build, source):
    commands = json.loads((build / 'compile_commands.json').read_text())
    compiled = {
        resolved(Path(item['directory']), item['file'])
        for item in commands
        if isinstance(item, dict)
        and isinstance(item.get('directory'), str)
        and isinstance(item.get('file'), str)
        and Path(item['file']).suffix.casefold() in SOURCE_SUFFIXES
    }
    if not compiled:
        raise ValueError('no C/C++ compile commands')
    info = build / 'meson-info'
    targets = json.loads((info / 'intro-targets.json').read_text())
    tests = json.loads((info / 'intro-tests.json').read_text())
    executable_targets = {}
    for target in targets:
        if not isinstance(target, dict) or target.get('type') != 'executable':
            continue
        source_paths = {
            resolved(source, raw)
            for group in target.get('target_sources', [])
            if isinstance(group, dict)
            and group.get('language') in {'c', 'cpp', 'c++', 'cxx'}
            for raw in group.get('sources', [])
            if isinstance(raw, str) and Path(raw).suffix.casefold() in SOURCE_SUFFIXES
        }
        if not any(within(source, path) for path in source_paths & compiled):
            continue
        filenames = target.get('filename') or []
        if isinstance(filenames, str):
            filenames = [filenames]
        for raw in filenames:
            if not isinstance(raw, str):
                continue
            artifact = resolved(build, raw)
            if not within(build, artifact):
                continue
            relative = artifact.relative_to(build.resolve()).as_posix()
            if not re.fullmatch(r'[A-Za-z0-9_./+-]{1,240}', relative):
                continue
            executable_targets[artifact] = relative
    eligible = []
    for test in tests:
        if not isinstance(test, dict) or test.get('protocol', 'exitcode') != 'exitcode':
            continue
        command = test.get('cmd') or []
        if not isinstance(command, list) or not command or not isinstance(command[0], str):
            continue
        artifact = resolved(build, command[0])
        target = executable_targets.get(artifact)
        if target is None:
            continue
        if len(command) > 64 or any(not isinstance(arg, str) or len(arg) > 4096 for arg in command):
            continue
        name = str(test.get('name') or '')
        eligible.append((len(command), len(target), name, {
            'artifact': str(artifact), 'target': target,
            'command': command, 'workdir': test.get('workdir'),
            'env': test.get('env') or {},
        }))
    if not eligible:
        raise ValueError('no Meson test backed by a compiled C/C++ executable')
    return sorted(eligible, key=lambda item: item[:3])[0][3]


if __name__ == '__main__':
    try:
        selected = select_meson_native_test(Path(sys.argv[1]), Path(sys.argv[2]))
        Path(sys.argv[3]).write_text(json.dumps(selected))
    except (OSError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise SystemExit(f'native Meson test selection failed: {exc}')
"""

VERIFY_MESON_NATIVE_TEST = r"""import json
import os
import subprocess
import sys
from pathlib import Path


def verify_meson_native_test(build, source, selection_path):
    selection = json.loads(selection_path.read_text())
    artifact = Path(selection['artifact']).resolve(strict=True)
    try:
        artifact.relative_to(build.resolve())
    except ValueError:
        raise ValueError('test executable escapes build directory')
    if not artifact.is_file() or not os.access(artifact, os.X_OK):
        raise ValueError('test executable is missing')
    with artifact.open('rb') as binary:
        header = binary.read(20)
    if len(header) < 20 or header[:4] != b'\x7fELF':
        raise ValueError('test executable is not ELF')
    endian = {1: 'little', 2: 'big'}.get(header[5])
    if endian is None or int.from_bytes(header[18:20], endian) != 183:
        raise ValueError('test executable is not AArch64')
    command = selection['command']
    if not isinstance(command, list) or not command or Path(command[0]).resolve() != artifact:
        raise ValueError('test command differs from selected executable')
    workdir = selection.get('workdir') or str(build)
    cwd = Path(workdir).resolve(strict=True)
    if not any(cwd == root.resolve() or root.resolve() in cwd.parents for root in (build, source)):
        raise ValueError('test working directory is outside source and build')
    extra_env = selection.get('env') or {}
    if not isinstance(extra_env, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in extra_env.items()
    ):
        raise ValueError('invalid Meson test environment')
    environment = os.environ.copy()
    environment.update(extra_env)
    result = subprocess.run(
        command, cwd=cwd, env=environment,
        capture_output=True, text=True, timeout=30, check=False,
    )
    print((result.stdout + result.stderr)[-8192:])
    if result.returncode != 0:
        raise ValueError('selected native Meson test did not pass')


if __name__ == '__main__':
    try:
        verify_meson_native_test(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    except (OSError, KeyError, TypeError, ValueError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(f'native Meson test smoke failed: {exc}')
"""

MESON_BUILD_AND_SMOKE = (
    """stage=configure
trap 'code=$?; if [ "$code" -ne 0 ]; then printf "FTS_ARM_PREFLIGHT_FAILED_STAGE:%s:%s\\n" "$stage" "$code" >&2; fi' EXIT
printf 'FTS_ARM_PREFLIGHT_STAGE:%s\\n' "$stage"
mkdir /work/src
cp -a /src/. /work/src/
CC=clang CXX=clang++ meson setup /work/build /work/src --backend=ninja --default-library=static --buildtype=release --wrap-mode=nodownload
stage=select_native_test
printf 'FTS_ARM_PREFLIGHT_STAGE:%s\\n' "$stage"
cat > /work/select_meson_native_test.py <<'PY'
"""
    + SELECT_MESON_NATIVE_TEST
    + """PY
python3 /work/select_meson_native_test.py /work/build /work/src /work/selection.json
target=$(python3 -c 'import json; print(json.load(open("/work/selection.json"))["target"])')
stage=build
printf 'FTS_ARM_PREFLIGHT_STAGE:%s\\n' "$stage"
ninja -C /work/build "$target"
stage=smoke
printf 'FTS_ARM_PREFLIGHT_STAGE:%s\\n' "$stage"
cat > /work/verify_meson_native_test.py <<'PY'
"""
    + VERIFY_MESON_NATIVE_TEST
    + """PY
python3 /work/verify_meson_native_test.py /work/build /work/src /work/selection.json
printf 'FTS_ARM_PREFLIGHT_OK\\n'
"""
)

MESON_PREFLIGHT_VERSION = hashlib.sha256(
    (MESON_DOCKERFILE + "\n" + MESON_BUILD_AND_SMOKE).encode("utf-8")
).hexdigest()[:16]
MESON_IMAGE_TAG = f"fts-arm-meson-preflight:{MESON_PREFLIGHT_VERSION}"


REPOSITORY_PART = re.compile(r"^[A-Za-z0-9_.-]+$")
COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")

# Infrastructure failures can clear without a change to the candidate's commit.
# Keep their retry interval short while preserving the configured cooldown for
# build and smoke failures that reflect the pinned source.
TRANSIENT_FAILURE_REASONS = frozenset({
    "checkout_failed",
    "builder_unavailable",
    "preflight_timeout",
    "preflight_unavailable_or_timed_out",
})

_FAILURE_STAGE = re.compile(
    r"(?m)^FTS_ARM_PREFLIGHT_FAILED_STAGE:"
    r"(configure|select_native_test|build|smoke):([0-9]{1,3})\r?$"
)
_LAST_STAGE = re.compile(
    r"(?m)^FTS_ARM_PREFLIGHT_STAGE:"
    r"(configure|select_native_test|build|smoke)\r?$"
)
_CTEST_FAILURE_COUNTS = re.compile(
    r"\b([0-9]{1,5}) tests? failed out of ([0-9]{1,5})\b",
    re.IGNORECASE,
)
_COMPILER_NOT_FOUND = re.compile(
    r"\bno CMAKE_(?:C|CXX)_COMPILER could be found\b"
    r"|\bthe CMAKE_(?:C|CXX)_COMPILER:\s*\S+\s+"
    r"is not a full path and was not found in the PATH\b"
    r"|(?m:^\s*(?:(?:/bin/)?(?:ba)?sh:\s*(?:[0-9]+:\s*)?)?"
    r"(?:clang\+\+|clang|g\+\+|gcc|c\+\+|cc):\s*"
    r"(?:command )?not found\b)",
    re.IGNORECASE,
)
_MISSING_HEADER_DEPENDENCY = re.compile(
    r"\b\S+\.(?:h|hpp) not found\b", re.IGNORECASE,
)


def _failure_evidence(output: str, returncode: int) -> str:
    """Keep only fixed diagnostic categories; build output is untrusted data.

    Repository CMake files, compilers and test executables can print credentials
    or arbitrary text. Never copy their lines, paths or target names to the cache.
    """
    failed = list(_FAILURE_STAGE.finditer(output))
    started = list(_LAST_STAGE.finditer(output))
    stage = (
        failed[-1].group(1) if failed else
        started[-1].group(1) if started else "unknown"
    )
    normalized = output.casefold()
    if returncode == 137 or "killed" in normalized:
        kind = "process_killed"
    elif "no space left on device" in normalized:
        kind = "disk_full"
    elif "cannot allocate memory" in normalized or "out of memory" in normalized:
        kind = "memory_exhausted"
    elif stage == "configure":
        if "fetchcontent" in normalized or "network is unreachable" in normalized:
            kind = "offline_dependency"
        elif _COMPILER_NOT_FOUND.search(output):
            kind = "compiler_unavailable"
        elif "could not find" in normalized or _MISSING_HEADER_DEPENDENCY.search(output):
            kind = "missing_dependency"
        else:
            kind = "configure_failed"
    elif stage == "select_native_test":
        if "no c/c++ compile commands" in normalized:
            kind = "no_native_compile_commands"
        elif "no meson test backed by a compiled c/c++ executable" in normalized:
            kind = "no_native_meson_test_target"
        elif "cmake file api reply is missing" in normalized or "cmake codemodel is missing" in normalized:
            kind = "missing_cmake_build_metadata"
        elif "no ctest executable backed by a c/c++ cmake target" in normalized:
            kind = "no_native_ctest_target"
        else:
            kind = "native_test_selection_failed"
    elif stage == "build":
        if "no such file or directory" in normalized and "fatal error:" in normalized:
            kind = "missing_header"
        elif "undefined reference" in normalized or "unresolved external" in normalized:
            kind = "link_error"
        elif "error:" in normalized:
            kind = "compile_error"
        else:
            kind = "build_failed"
    elif stage == "smoke":
        if "not aarch64" in normalized:
            kind = "wrong_test_architecture"
        elif "test executable is missing" in normalized:
            kind = "test_executable_missing"
        elif "timeout" in normalized or "timed out" in normalized:
            kind = "ctest_timeout"
        elif "selected native meson test did not pass" in normalized:
            kind = "meson_test_failed"
        elif _CTEST_FAILURE_COUNTS.search(output) or "selected native ctest did not pass" in normalized:
            kind = "ctest_failed"
        else:
            kind = "smoke_failed"
    else:
        kind = "container_command_failed"
    evidence = f"native_arm_failure:stage={stage};kind={kind};exit={int(returncode)}"
    if stage == "smoke" and kind == "ctest_failed":
        counts = _CTEST_FAILURE_COUNTS.search(output)
        if counts:
            evidence += f";failed_tests={int(counts[1])}/{int(counts[2])}"
    return evidence


def _working_tree_within_limit(source: Path, maximum_bytes: int) -> bool:
    """Measure checked-out files without visiting Git metadata or link targets."""
    total = 0
    pending = [source]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                if entry.name == ".git":
                    continue
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    total += info.st_size
                    if total > maximum_bytes:
                        return False
                else:
                    return False
    return True


@dataclass(frozen=True, slots=True)
class ArmPreflightResult:
    passed: bool
    reason: str
    evidence: str = ""


class _StepFailure(Exception):
    def __init__(self, reason: str, evidence: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.evidence = evidence


class ArmPreflight:
    """Prove a pinned C/C++ checkout builds and runs a test on native ARM."""

    def __init__(
        self,
        architecture_config: dict,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.config = architecture_config
        self.progress = progress or (lambda _message: None)

    @staticmethod
    def _safe_repository(name: str) -> bool:
        parts = name.split("/")
        return len(parts) == 2 and all(
            part not in {".", ".."} and REPOSITORY_PART.fullmatch(part)
            for part in parts
        )

    def check(self, repo: RepoSnapshot) -> ArmPreflightResult:
        host_arch = resolve_host_architecture(self.config)
        if (
            host_arch != "aarch64"
            or normalize_architecture(platform.machine()) != "aarch64"
        ):
            return ArmPreflightResult(False, "not_native_arm_host")
        if not self._safe_repository(repo.full_name) or not COMMIT.fullmatch(repo.head_sha):
            return ArmPreflightResult(False, "invalid_pinned_source")
        maximum_kb = min(
            100000, max(1, int(self.config.get("arm_preflight_max_repository_kb", 50000)))
        )
        source_tree_kb = getattr(repo, "source_tree_kb", None)
        estimated_kb = repo.size_kb if source_tree_kb is None else source_tree_kb
        if (
            not isinstance(estimated_kb, int)
            or isinstance(estimated_kb, bool)
            or not 0 < estimated_kb <= maximum_kb
        ):
            return ArmPreflightResult(False, "repository_size_out_of_bounds")
        deadline = time.monotonic() + min(
            1800, max(60, int(self.config.get("arm_preflight_timeout_seconds", 900)))
        )
        with tempfile.TemporaryDirectory(prefix="fts-arm-preflight-") as directory:
            root = Path(directory)
            checkout = root / "source"
            checkout.mkdir()
            # The service may run with UMask=0077. Docker uses an unprivileged
            # UID and needs to traverse the bind-mounted source directory.
            # Keep the TemporaryDirectory parent private.
            checkout.chmod(0o755)
            url = f"https://github.com/{repo.full_name}.git"
            environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(root),
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
            }
            try:
                self.progress(f"ARM preflight checking pinned source for {repo.full_name}")
                self._run(["git", "init", "--quiet", str(checkout)], deadline, environment, "checkout_failed")
                self._run(
                    ["git", "-C", str(checkout), "remote", "add", "origin", url],
                    deadline, environment, "checkout_failed",
                )
                self._run(
                    ["git", "-C", str(checkout), "-c", "credential.helper=",
                     "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
                     "fetch", "--depth", "1", "origin", repo.head_sha],
                    deadline, environment, "checkout_failed",
                )
                self._run(
                    ["git", "-C", str(checkout), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
                    deadline, environment, "checkout_failed",
                )
                actual = self._run(
                    ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                    deadline, environment, "checkout_failed",
                ).stdout.strip()
                if actual.casefold() != repo.head_sha.casefold():
                    raise _StepFailure("checkout_mismatch")
                if not _working_tree_within_limit(checkout, maximum_kb * 1024):
                    raise _StepFailure("repository_size_out_of_bounds")
                cmake_file = checkout / "CMakeLists.txt"
                meson_file = checkout / "meson.build"
                if cmake_file.is_file() and not cmake_file.is_symlink():
                    build_system = "cmake"
                    image_tag = IMAGE_TAG
                    dockerfile = DOCKERFILE
                    build_and_smoke = BUILD_AND_SMOKE
                    version = PREFLIGHT_VERSION
                elif meson_file.is_file() and not meson_file.is_symlink():
                    build_system = "meson"
                    image_tag = MESON_IMAGE_TAG
                    dockerfile = MESON_DOCKERFILE
                    build_and_smoke = MESON_BUILD_AND_SMOKE
                    version = MESON_PREFLIGHT_VERSION
                else:
                    raise _StepFailure("no_root_cmake_build")
                self._ensure_builder(
                    root, deadline, environment,
                    image_tag=image_tag, dockerfile=dockerfile,
                )
                container_name = "fts-arm-probe-" + uuid.uuid4().hex[:16]
                command = [
                    "docker", "run", "--rm", "--name", container_name,
                    "--network", "none", "--read-only", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges:true",
                    "--pids-limit", "256", "--cpus", "2", "--memory", "2048m",
                    "--memory-swap", "2048m", "--user", "65534:65534",
                    "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
                    "--tmpfs", "/work:rw,exec,nosuid,size=1024m,uid=65534,gid=65534",
                    "--mount", f"type=bind,source={checkout},target=/src,readonly",
                    "--workdir", "/work", "--env", "HOME=/work",
                    image_tag, "/bin/sh", "-ec", build_and_smoke,
                ]
                try:
                    result = self._run(
                        command, deadline, environment, "native_build_or_smoke_failed"
                    )
                finally:
                    # subprocess timeout kills the Docker client, not necessarily
                    # the container. Always remove the named container.
                    subprocess.run(
                        ["docker", "rm", "-f", container_name],
                        env=environment, capture_output=True, text=True,
                        timeout=20, check=False,
                    )
                if "FTS_ARM_PREFLIGHT_OK" not in result.stdout:
                    raise _StepFailure(
                        "smoke_marker_missing",
                        "native_arm_failure:stage=smoke;kind=success_marker_missing;exit=0",
                    )
            except _StepFailure as exc:
                return ArmPreflightResult(False, exc.reason, exc.evidence)
            except (OSError, subprocess.TimeoutExpired, ValueError):
                return ArmPreflightResult(False, "preflight_unavailable_or_timed_out")
        return ArmPreflightResult(
            True,
            f"native_arm_build_and_{'ctest' if build_system == 'cmake' else 'meson_test'}_passed",
            f"native_arm_preflight:{version}:{build_system}_build_"
            f"{'ctest' if build_system == 'cmake' else 'meson_test'}:{repo.head_sha.lower()}",
        )

    def _ensure_builder(
        self, root: Path, deadline: float, environment: dict[str, str],
        *, image_tag: str = IMAGE_TAG, dockerfile: str = DOCKERFILE,
    ) -> None:
        inspected = self._try_run(
            ["docker", "image", "inspect", "--format", "{{.Architecture}}", image_tag],
            deadline, environment,
        )
        if inspected is None:
            context = root / "builder-context"
            context.mkdir()
            (context / "Dockerfile").write_text(dockerfile, encoding="utf-8")
            self._run(
                ["docker", "build", "--pull", "--tag", image_tag, str(context)],
                deadline, environment, "builder_unavailable",
            )
            inspected = self._try_run(
                ["docker", "image", "inspect", "--format", "{{.Architecture}}", image_tag],
                deadline, environment,
            )
        if inspected is None or normalize_architecture(inspected.stdout.strip()) != "aarch64":
            raise _StepFailure("builder_architecture_mismatch")

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _StepFailure("preflight_timeout")
        return remaining

    def _try_run(
        self, command: list[str], deadline: float, environment: dict[str, str],
        *, preserve_failure: bool = False,
    ) -> subprocess.CompletedProcess[str] | None:
        output = bytearray()
        process = None
        try:
            process = subprocess.Popen(
                command, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                start_new_session=True, umask=0o022,
            )
            assert process.stdout is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = self._remaining(deadline)
                    for key, _events in selector.select(min(remaining, 0.5)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        output.extend(chunk)
                        if len(output) > 65536:
                            del output[:-65536]
            returncode = process.wait(timeout=self._remaining(deadline))
        except (_StepFailure, subprocess.TimeoutExpired) as exc:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise _StepFailure("preflight_timeout") from exc
        except OSError as exc:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise _StepFailure("preflight_unavailable_or_timed_out") from exc
        finally:
            if process is not None and process.stdout is not None:
                process.stdout.close()
        result = subprocess.CompletedProcess(
            command, returncode, output.decode("utf-8", errors="replace"), ""
        )
        return result if result.returncode == 0 or preserve_failure else None

    def _run(
        self, command: list[str], deadline: float,
        environment: dict[str, str], failure: str,
    ) -> subprocess.CompletedProcess[str]:
        result = self._try_run(
            command, deadline, environment, preserve_failure=True
        )
        if result is None:
            raise _StepFailure(failure)
        if result.returncode != 0:
            # Docker returns 125 when its own run operation fails before the
            # container command starts. This is not evidence of a bad source build.
            reason = (
                "builder_unavailable"
                if command[:2] == ["docker", "run"] and result.returncode == 125
                else failure
            )
            evidence = ""
            if command[:2] == ["docker", "run"]:
                evidence = (
                    "native_arm_failure:stage=container_start;kind=docker_start_failed;exit=125"
                    if reason == "builder_unavailable"
                    else _failure_evidence(result.stdout, result.returncode)
                )
            raise _StepFailure(reason, evidence)
        return result
