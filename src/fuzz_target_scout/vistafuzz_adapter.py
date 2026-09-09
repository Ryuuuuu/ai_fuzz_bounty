from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .pipeline import PipelineError, load_toolchain_lock, utc_now


class VistaFuzzAdapter:
    """Pinned adapter for the OpenCV-specific VistaFuzz research artifact."""

    def __init__(self, config: dict[str, Any]):
        self.pipeline = config["pipeline"]
        self.tools_root = Path(self.pipeline["tools_path"])

    def inspect(self) -> dict[str, Any]:
        lock = load_toolchain_lock(self.pipeline["toolchain_lock_path"])
        tool = lock["tools"]["vistafuzz"]
        expected = str(tool["commit"])
        checkout = self.tools_root / "vistafuzz"
        if not (checkout / ".git").is_dir():
            self._sync_checkout(checkout, tool)
        testing = checkout / "OpenCV-Testing"
        required = [
            testing / "Dockerfile",
            testing / "main.py",
            testing / "API" / "OpenCV_API_filtered_subset.json",
            testing / "tool" / "API_info.py",
        ]
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise PipelineError(
                "pinned VistaFuzz checkout is incomplete: " + ", ".join(missing)
            )
        actual = _capture(["git", "-C", str(checkout), "rev-parse", "HEAD"])
        if actual.casefold() != expected.casefold():
            raise PipelineError("VistaFuzz checkout does not match toolchain.lock.json")
        api_path = required[2]
        api_count, api_format_valid = _api_metadata_status(api_path)
        return {
            "schema_version": 1,
            "created_at": utc_now(),
            "tool_commit": actual,
            "artifact": "OpenCV-Python_document_guided_fuzzing",
            "api_count": api_count,
            "api_format_valid": api_format_valid,
            "api_metadata_sha256": _sha256(api_path),
            "dockerfile_sha256": _sha256(required[0]),
            "generic_python_support": False,
            "bounty_evidence_eligible": False,
            "reason": "the upstream artifact builds and tests its own OpenCV environment rather than an arbitrary pinned target checkout",
        }

    def smoke(self, seconds: int) -> dict[str, Any]:
        if not bool(self.pipeline.get("vistafuzz_enabled", False)):
            raise PipelineError("set pipeline.vistafuzz_enabled=true to run the research artifact")
        if seconds < 1 or seconds > int(self.pipeline.get("vistafuzz_seconds", 3600)):
            raise PipelineError("VistaFuzz smoke duration is outside the configured limit")
        inspected = self.inspect()
        checkout = self.tools_root / "vistafuzz" / "OpenCV-Testing"
        output = Path(self.pipeline["runs_path"]) / "vistafuzz-artifact"
        work = output / "work"
        logs = output / "logs"
        if work.exists():
            shutil.rmtree(work)
        logs.mkdir(parents=True, exist_ok=True)
        shutil.copytree(checkout, work, symlinks=False)
        if not inspected["api_format_valid"]:
            api_path = work / "API" / "OpenCV_API_filtered_subset.json"
            names = _extract_api_names(api_path.read_text(encoding="utf-8", errors="replace"))
            api_path.write_text(json.dumps(names, indent=2) + "\n", encoding="utf-8")
        tag = "fuzz-target-scout/vistafuzz:" + inspected["tool_commit"][:12]
        build_log = logs / "build.log"
        _run(["docker", "build", "--tag", tag, str(work)], build_log, 7200)
        name = "fts-vistafuzz-" + str(time.time_ns())[-12:]
        run_log = logs / "smoke.log"
        command = [
            "docker", "run", "--rm", "--name", name,
            "--label", "fuzz-target-scout=true",
            "--label", "fuzz-target-scout.job=vistafuzz-artifact",
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "512",
            "--cpus", "2", "--memory", f"{int(self.pipeline['container_memory_mb'])}m",
            "--tmpfs", "/tmp:rw,exec,nosuid,size=1g",
            "-v", f"{work}:/app:rw", tag, "bash", "-lc",
            f"cd /app && timeout {seconds}s python3 main.py",
        ]
        try:
            exit_code = _run(command, run_log, seconds + 180, accepted={0, 124})
        except Exception:
            subprocess.run(
                ["docker", "rm", "-f", name], capture_output=True, text=True,
                timeout=30, check=False, env=_safe_environment(),
            )
            raise
        result = {
            **inspected,
            "completed_at": utc_now(),
            "requested_seconds": seconds,
            "exit_code": exit_code,
            "status": "completed" if exit_code in {0, 124} else "failed",
            "log_path": str(run_log),
            "bounty_evidence_eligible": False,
        }
        _write_json(output / "result.json", result)
        return result

    @staticmethod
    def _sync_checkout(checkout: Path, tool: dict[str, Any]) -> None:
        url = str(tool.get("url") or "")
        commit = str(tool.get("commit") or "")
        if url != "https://github.com/beanduan22/VistaFuzz.git":
            raise PipelineError("unexpected VistaFuzz tool URL")
        if checkout.exists():
            raise PipelineError("incomplete VistaFuzz checkout exists; remove it before syncing")
        checkout.parent.mkdir(parents=True, exist_ok=True)
        _capture(["git", "clone", "--filter=blob:none", "--no-checkout", url, str(checkout)])
        _capture(["git", "-C", str(checkout), "fetch", "--depth", "1", "origin", commit])
        _capture(["git", "-C", str(checkout), "checkout", "--detach", "FETCH_HEAD"])


def _capture(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8",
            timeout=30, check=False, env=_safe_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PipelineError(f"command failed: {exc}") from exc
    if result.returncode != 0:
        raise PipelineError((result.stderr or result.stdout).strip()[-2000:])
    return result.stdout.strip()


def _run(
    command: list[str], log_path: Path, timeout: int, accepted: set[int] | None = None
) -> int:
    accepted = accepted or {0}
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, check=False, env=_safe_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PipelineError(f"VistaFuzz command failed: {exc}") from exc
    log_path.write_text((result.stdout or "") + (result.stderr or ""), encoding="utf-8")
    if result.returncode not in accepted:
        raise PipelineError(f"VistaFuzz command exited with {result.returncode}")
    return result.returncode


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _api_metadata_status(path: Path) -> tuple[int, bool]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PipelineError(f"could not read VistaFuzz API metadata: {exc}") from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        names = _extract_api_names(text)
        if not names:
            raise PipelineError("VistaFuzz API metadata has no recognizable cv2 API names")
        return len(names), False
    return (len(value) if isinstance(value, (list, dict)) else 0), True


def _extract_api_names(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r'"(cv2\.[A-Za-z0-9_]+)"', text)))


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _safe_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "CODEX_API_KEY"):
        environment.pop(name, None)
    return environment
