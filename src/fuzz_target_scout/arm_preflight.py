from __future__ import annotations

import hashlib
import os
import platform
import re
import selectors
import signal
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
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends clang cmake ninja-build build-essential pkg-config python3 ca-certificates libgtest-dev && rm -rf /var/lib/apt/lists/*
"""

# Project-controlled CMake code runs only inside the restricted, networkless
# container. A successful configure alone is never ARM compatibility evidence.
BUILD_AND_SMOKE = """cmake -S /src -B /work/build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DBUILD_TESTING=ON -DFETCHCONTENT_FULLY_DISCONNECTED=ON
cmake --build /work/build --parallel 2
ctest --test-dir /work/build -N | grep -Eq '^Total Tests: [1-9][0-9]*$'
ctest --test-dir /work/build --output-on-failure -I 1,1 --timeout 30 > /work/smoke.log 2>&1
grep -Eq '^100% tests passed, 0 tests failed out of 1$' /work/smoke.log
printf 'FTS_ARM_PREFLIGHT_OK\\n'
"""

PREFLIGHT_VERSION = hashlib.sha256(
    (DOCKERFILE + "\n" + BUILD_AND_SMOKE).encode("utf-8")
).hexdigest()[:16]
IMAGE_TAG = f"fts-arm-preflight:{PREFLIGHT_VERSION}"
REPOSITORY_PART = re.compile(r"^[A-Za-z0-9_.-]+$")
COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True, slots=True)
class ArmPreflightResult:
    passed: bool
    reason: str
    evidence: str = ""


class _StepFailure(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


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
        if not 0 < repo.size_kb <= maximum_kb:
            return ArmPreflightResult(False, "repository_size_out_of_bounds")
        deadline = time.monotonic() + min(
            1800, max(60, int(self.config.get("arm_preflight_timeout_seconds", 900)))
        )
        with tempfile.TemporaryDirectory(prefix="fts-arm-preflight-") as directory:
            root = Path(directory)
            checkout = root / "source"
            checkout.mkdir()
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
                build_file = checkout / "CMakeLists.txt"
                if not build_file.is_file() or build_file.is_symlink():
                    raise _StepFailure("no_root_cmake_build")
                self._ensure_builder(root, deadline, environment)
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
                    IMAGE_TAG, "/bin/sh", "-ec", BUILD_AND_SMOKE,
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
                    raise _StepFailure("smoke_marker_missing")
            except _StepFailure as exc:
                return ArmPreflightResult(False, exc.reason)
            except (OSError, subprocess.TimeoutExpired, ValueError):
                return ArmPreflightResult(False, "preflight_unavailable_or_timed_out")
        return ArmPreflightResult(
            True,
            "native_arm_build_and_ctest_passed",
            f"native_arm_preflight:{PREFLIGHT_VERSION}:cmake_build_ctest:{repo.head_sha.lower()}",
        )

    def _ensure_builder(self, root: Path, deadline: float, environment: dict[str, str]) -> None:
        inspected = self._try_run(
            ["docker", "image", "inspect", "--format", "{{.Architecture}}", IMAGE_TAG],
            deadline, environment,
        )
        if inspected is None:
            context = root / "builder-context"
            context.mkdir()
            (context / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
            self._run(
                ["docker", "build", "--pull", "--tag", IMAGE_TAG, str(context)],
                deadline, environment, "builder_unavailable",
            )
            inspected = self._try_run(
                ["docker", "image", "inspect", "--format", "{{.Architecture}}", IMAGE_TAG],
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
        self, command: list[str], deadline: float, environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str] | None:
        output = bytearray()
        process = None
        try:
            process = subprocess.Popen(
                command, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                start_new_session=True,
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
        except (_StepFailure, OSError, subprocess.TimeoutExpired):
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            return None
        finally:
            if process is not None and process.stdout is not None:
                process.stdout.close()
        result = subprocess.CompletedProcess(
            command, returncode, output.decode("utf-8", errors="replace"), ""
        )
        return result if result.returncode == 0 else None

    def _run(
        self, command: list[str], deadline: float,
        environment: dict[str, str], failure: str,
    ) -> subprocess.CompletedProcess[str]:
        result = self._try_run(command, deadline, environment)
        if result is None:
            raise _StepFailure(failure)
        return result
