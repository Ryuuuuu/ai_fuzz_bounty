from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .pipeline import PipelineError, job_status, list_jobs, utc_now


EVIDENCE_DIRECTORIES = {"artifacts", "crashes", "validation", "poc"}


def pipeline_overview(runs_root: str | Path) -> dict[str, Any]:
    root = Path(runs_root)
    records: list[dict[str, Any]] = []
    for summary in list_jobs(root):
        try:
            record = job_status(root, str(summary["job_id"]))
        except PipelineError:
            continue
        record["disk_bytes"] = directory_size(root / str(summary["job_id"]))
        records.append(record)
    records.sort(key=lambda item: (str(item.get("updated_at") or ""), item["job_id"]))
    status_counts: dict[str, int] = {}
    for item in records:
        key = str(item.get("status") or "unknown")
        status_counts[key] = status_counts.get(key, 0) + 1
    return {
        "schema_version": 1,
        "created_at": utc_now(),
        "runs_root": str(root.resolve()),
        "job_count": len(records),
        "status_counts": dict(sorted(status_counts.items())),
        "total_disk_bytes": sum(int(item["disk_bytes"]) for item in records),
        "jobs": records,
    }


def directory_size(root: Path) -> int:
    if root.is_symlink() or not root.is_dir():
        return 0
    total = 0
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        names[:] = [name for name in names if not (current / name).is_symlink()]
        for name in files:
            path = current / name
            try:
                if not path.is_symlink() and path.is_file():
                    total += path.stat().st_size
            except OSError:
                continue
    return total


class Housekeeper:
    def __init__(self, config: dict[str, Any]):
        self.pipeline = config["pipeline"]
        self.runs_root = Path(self.pipeline["runs_path"])

    def run(self, job_id: str | None = None) -> dict[str, Any]:
        self.runs_root.mkdir(parents=True, exist_ok=True)
        jobs = [self._job_dir(job_id)] if job_id else self._job_dirs()
        records = [self._clean_job(path) for path in jobs]
        removed_containers = self._clean_orphan_containers()
        return {
            "schema_version": 1,
            "created_at": utc_now(),
            "jobs": records,
            "removed_orphan_containers": removed_containers,
        }

    def _job_dirs(self) -> list[Path]:
        return sorted(
            path.parent
            for path in self.runs_root.glob("*/state.json")
            if not path.parent.is_symlink()
        )

    def _job_dir(self, job_id: str) -> Path:
        if not job_id or Path(job_id).name != job_id:
            raise PipelineError("invalid housekeeping job id")
        root = self.runs_root.resolve()
        path = self.runs_root / job_id
        if path.is_symlink() or not path.is_dir() or path.resolve().parent != root:
            raise PipelineError(f"job directory was not found: {path}")
        return path.resolve()

    def _clean_job(self, job_dir: Path) -> dict[str, Any]:
        before = directory_size(job_dir)
        removed_files = 0
        removed_bytes = 0
        for corpus in sorted((job_dir / "corpus").glob("*")):
            count, size = self._prune_files(
                corpus,
                int(self.pipeline["corpus_max_files"]),
                int(self.pipeline["corpus_limit_mb"]) * 1024 * 1024,
            )
            removed_files += count
            removed_bytes += size
        count, size = self._prune_files(
            job_dir / "logs", int(self.pipeline["log_max_files"]), None
        )
        removed_files += count
        removed_bytes += size
        state = self._read_state(job_dir)
        if state.get("stage") == "complete":
            age = time.time() - self._mtime(job_dir / "state.json")
            if age >= int(self.pipeline["runtime_retention_hours"]) * 3600:
                runtime = job_dir / "runtime-out"
                if runtime.is_dir() and not runtime.is_symlink():
                    size = directory_size(runtime)
                    shutil.rmtree(runtime)
                    removed_bytes += size
        after = directory_size(job_dir)
        limit = int(self.pipeline["job_disk_limit_mb"]) * 1024 * 1024
        over_limit = after > limit
        if over_limit and state.get("stage") != "complete":
            state["status"] = "resource_limit_required"
            state["last_error"] = (
                f"job uses {after} bytes, above configured limit {limit}"
            )
            state["updated_at"] = utc_now()
            self._write_state(job_dir, state)
        return {
            "job_id": job_dir.name,
            "before_bytes": before,
            "after_bytes": after,
            "removed_files": removed_files,
            "removed_bytes": removed_bytes,
            "over_limit": over_limit,
        }

    @staticmethod
    def _prune_files(
        root: Path, max_files: int, max_bytes: int | None
    ) -> tuple[int, int]:
        if root.is_symlink() or not root.is_dir():
            return 0, 0
        files = []
        for path in root.rglob("*"):
            try:
                if not path.is_symlink() and path.is_file():
                    stat = path.stat()
                    files.append((stat.st_mtime_ns, path, stat.st_size))
            except OSError:
                continue
        files.sort(key=lambda item: (item[0], item[1].as_posix()), reverse=True)
        kept_bytes = 0
        removed_files = 0
        removed_bytes = 0
        for index, (_, path, size) in enumerate(files):
            keep = index < max(0, max_files)
            if max_bytes is not None and kept_bytes + size > max(0, max_bytes):
                keep = False
            if keep:
                kept_bytes += size
                continue
            path.unlink(missing_ok=True)
            removed_files += 1
            removed_bytes += size
        return removed_files, removed_bytes

    def _clean_orphan_containers(self) -> list[str]:
        active = self._active_containers()
        try:
            result = subprocess.run(
                [
                    "docker", "ps", "-a", "--filter", "label=fuzz-target-scout=true",
                    "--format", "{{.Names}}",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if result.returncode != 0:
            return []
        removed: list[str] = []
        for name in sorted(set(result.stdout.splitlines()) - active):
            if not name.startswith("fts-"):
                continue
            cleanup = subprocess.run(
                ["docker", "rm", "-f", name],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                check=False,
            )
            if cleanup.returncode == 0:
                removed.append(name)
        return removed

    def _active_containers(self) -> set[str]:
        result: set[str] = set()
        for job_dir in self._job_dirs():
            state = self._read_state(job_dir)
            if state.get("status") not in {"running", "afl_cmplog_running"}:
                continue
            for key in ("active_fuzz_container", "active_afl_container"):
                value = str(state.get(key) or "")
                if value.startswith("fts-"):
                    result.add(value)
        return result

    @staticmethod
    def _mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return time.time()

    @staticmethod
    def _read_state(job_dir: Path) -> dict[str, Any]:
        try:
            value = json.loads((job_dir / "state.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _write_state(job_dir: Path, value: dict[str, Any]) -> None:
        path = job_dir / "state.json"
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
