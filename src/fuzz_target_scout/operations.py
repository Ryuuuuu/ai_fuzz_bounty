from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .pipeline import PipelineError, PipelineInterrupted, job_status, list_jobs, utc_now


EVIDENCE_DIRECTORIES = {"artifacts", "crashes", "validation", "poc"}
TRANSIENT_WORK_DIRECTORIES = (
    "runtime-out",
    "native-work",
    "native-out",
    "build-output",
    "build-source",
    "source",
)


MERGE_MAX_INPUT_FILES = 200_000
MERGE_MAX_INPUT_BYTES = 8 * 1024 * 1024 * 1024
MERGE_TIMEOUT_SECONDS = 600


def _check_cancel(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise PipelineInterrupted("housekeeping stopped by operator")


def pipeline_overview(
    runs_root: str | Path, *, cancel_event: threading.Event | None = None,
    include_disk_usage: bool = True,
) -> dict[str, Any]:
    root = Path(runs_root)
    records: list[dict[str, Any]] = []
    for summary in list_jobs(root):
        _check_cancel(cancel_event)
        try:
            record = job_status(root, str(summary["job_id"]))
        except PipelineError:
            continue
        record["disk_bytes"] = (
            directory_size(root / str(summary["job_id"]), cancel_event=cancel_event)
            if include_disk_usage else None
        )
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
        "total_disk_bytes": (
            sum(int(item["disk_bytes"]) for item in records)
            if include_disk_usage else None
        ),
        "disk_usage_complete": include_disk_usage,
        "jobs": records,
    }


def directory_size(
    root: Path, *, cancel_event: threading.Event | None = None
) -> int:
    _check_cancel(cancel_event)
    if root.is_symlink() or not root.is_dir():
        return 0
    total = 0
    for directory, names, files in os.walk(root, followlinks=False):
        _check_cancel(cancel_event)
        current = Path(directory)
        names[:] = [name for name in names if not (current / name).is_symlink()]
        for name in files:
            _check_cancel(cancel_event)
            path = current / name
            try:
                if not path.is_symlink() and path.is_file():
                    total += path.stat().st_size
            except OSError:
                continue
    return total


class Housekeeper:
    def __init__(
        self, config: dict[str, Any], cancel_event: threading.Event | None = None
    ):
        self.pipeline = config["pipeline"]
        self.runs_root = Path(self.pipeline["runs_path"])
        self.cancel_event = cancel_event

    def run(
        self, job_id: str | None = None, *, clean_orphan_containers: bool = True,
        completed_only: bool = False,
    ) -> dict[str, Any]:
        self._check_cancel()
        self.runs_root.mkdir(parents=True, exist_ok=True)
        with (self.runs_root / ".housekeeper.lock").open("a+b") as lock:
            self._check_cancel()
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {
                    "schema_version": 1,
                    "created_at": utc_now(),
                    "jobs": [],
                    "removed_orphan_containers": [],
                    "skipped_busy": True,
                }
            jobs = [self._job_dir(job_id)] if job_id else self._job_dirs()
            records = []
            for path in jobs:
                self._check_cancel()
                if completed_only:
                    state = self._read_state(path)
                    if state.get("stage") != "complete" or (
                        state.get("active_fuzz_container")
                        or state.get("active_afl_container")
                    ):
                        continue
                records.append(self._clean_job(path))
            self._check_cancel()
            removed_containers = (
                self._clean_orphan_containers() if clean_orphan_containers else []
            )
            return {
                "schema_version": 1,
                "created_at": utc_now(),
                "jobs": records,
                "removed_orphan_containers": removed_containers,
                "skipped_busy": False,
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

    def _check_cancel(self) -> None:
        _check_cancel(self.cancel_event)

    def _clean_job(self, job_dir: Path) -> dict[str, Any]:
        self._check_cancel()
        before = directory_size(job_dir, cancel_event=self.cancel_event)
        removed_files = 0
        removed_bytes = 0
        removed_workspaces: list[str] = []
        state = self._read_state(job_dir)
        compactions: list[dict[str, Any]] = []
        corpus_over_limit = False
        for corpus in sorted((job_dir / "corpus").glob("*")):
            self._check_cancel()
            if corpus.is_symlink() or not corpus.is_dir():
                continue
            result = self._compact_corpus(job_dir, corpus, state)
            if result is None:
                continue
            compactions.append(result)
            corpus_over_limit |= bool(result["over_limit"])
            removed_files += int(result["removed_files"])
            removed_bytes += int(result["removed_bytes"])
        count, size = self._prune_files(
            job_dir / "logs", int(self.pipeline["log_max_files"]), None,
            cancel_event=self.cancel_event,
        )
        removed_files += count
        removed_bytes += size
        if state.get("stage") == "complete":
            age = time.time() - self._mtime(job_dir / "state.json")
            if age >= int(self.pipeline["runtime_retention_hours"]) * 3600:
                for name in TRANSIENT_WORK_DIRECTORIES:
                    self._check_cancel()
                    workspace = job_dir / name
                    if not workspace.is_dir() or workspace.is_symlink():
                        continue
                    size = directory_size(workspace, cancel_event=self.cancel_event)
                    self._check_cancel()
                    shutil.rmtree(workspace)
                    removed_bytes += size
                    removed_workspaces.append(name)
        after = directory_size(job_dir, cancel_event=self.cancel_event)
        limit = int(self.pipeline["job_disk_limit_mb"]) * 1024 * 1024
        over_limit = after > limit or corpus_over_limit
        state = self._read_state(job_dir)
        active = bool(
            state.get("active_fuzz_container") or state.get("active_afl_container")
        )
        if over_limit and state.get("stage") != "complete" and not active:
            state["status"] = "resource_limit_required"
            state["last_error"] = (
                f"job uses {after} bytes, above configured limit {limit}"
                if after > limit else "corpus exceeds configured limit; safe merge unavailable"
            )
            state["updated_at"] = utc_now()
            self._write_state(job_dir, state)
        return {
            "job_id": job_dir.name,
            "before_bytes": before,
            "after_bytes": after,
            "removed_files": removed_files,
            "removed_bytes": removed_bytes,
            "removed_workspaces": removed_workspaces,
            "corpus_compactions": compactions,
            "over_limit": over_limit,
        }

    def _compact_corpus(
        self, job_dir: Path, corpus: Path, state: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Discard inputs only after bounded libFuzzer merging proves redundancy."""
        max_files = max(0, int(self.pipeline["corpus_max_files"]))
        max_bytes = max(0, int(self.pipeline["corpus_limit_mb"])) * 1024 * 1024
        try:
            snapshot: list[tuple[Path, os.stat_result]] = []
            file_count = 0
            total_bytes = 0
            unsafe = False

            def raise_walk_error(error: OSError) -> None:
                raise error

            for directory, names, files in os.walk(
                corpus, followlinks=False, onerror=raise_walk_error
            ):
                self._check_cancel()
                current = Path(directory)
                if current != corpus or any((current / name).is_symlink() for name in names):
                    unsafe = True
                for name in files:
                    self._check_cancel()
                    path = current / name
                    if path.is_symlink() or not path.is_file():
                        unsafe = True
                        continue
                    stat = path.stat()
                    file_count += 1
                    total_bytes += stat.st_size
                    if file_count <= MERGE_MAX_INPUT_FILES:
                        snapshot.append((path, stat))
                    if (
                        (file_count > MERGE_MAX_INPUT_FILES or total_bytes > MERGE_MAX_INPUT_BYTES)
                        and (file_count > max_files or total_bytes > max_bytes)
                    ):
                        result = self._compaction_result(corpus, "merge_input_cap_exceeded")
                        result.update(before_files=file_count, before_bytes=total_bytes)
                        return result
        except OSError:
            return self._compaction_result(corpus, "corpus_unreadable")
        if file_count <= max_files and total_bytes <= max_bytes:
            return None
        result = self._compaction_result(corpus, "unsafe_corpus" if unsafe else "merge_unavailable")
        result.update(before_files=file_count, before_bytes=total_bytes)
        if unsafe:
            return result
        snapshot.sort(key=lambda item: item[0])
        if state.get("active_fuzz_container") or state.get("active_afl_container"):
            result["status"] = "active_fuzz_deferred"
            return result
        if file_count > MERGE_MAX_INPUT_FILES or total_bytes > MERGE_MAX_INPUT_BYTES:
            result["status"] = "merge_input_cap_exceeded"
            return result
        try:
            manifest = json.loads(
                (job_dir / "artifacts" / "build-manifest.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            return result
        if not isinstance(manifest, dict) or manifest.get("execution_mode") != "native_container":
            return result
        target = corpus.name
        targets = manifest.get("fuzz_targets")
        if not isinstance(targets, list) or target not in targets:
            return result
        image = str(manifest.get("runner_image") or "")
        out_dir = Path(str(manifest.get("output_directory") or "")).resolve()
        if not image or not out_dir.is_relative_to(job_dir.resolve()):
            return result
        binary = out_dir / target
        if binary.is_symlink() or not binary.is_file():
            return result
        try:
            if shutil.disk_usage(corpus).free < total_bytes + 64 * 1024 * 1024:
                result["status"] = "merge_disk_space_required"
                return result
        except OSError:
            return result
        name = f"fts-merge-{uuid.uuid4().hex[:16]}"
        deadline = time.monotonic() + MERGE_TIMEOUT_SECONDS
        try:
            temporary = tempfile.TemporaryDirectory(
                prefix=".fts-merge-", dir=corpus.parent
            )
        except OSError:
            result["status"] = "merge_temporary_directory_failed"
            return result
        try:
            merged = Path(temporary.name)
            command = [
                "docker", "run", "--rm", "--pull", "never", "--name", name,
                "--network", "none", "--read-only", "--cpus", "1",
                "--memory", "1536m", "--pids-limit", "64",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--tmpfs", "/tmp:rw,exec,nosuid,size=64m",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--workdir", "/out",
                "-v", f"{out_dir}:/out:ro",
                "-v", f"{corpus}:/merge-input:ro",
                "-v", f"{merged}:/merge-output:rw",
                image, f"/out/{target}", "-merge=1", "-timeout=10",
                "-rss_limit_mb=1024", "/merge-output", "/merge-input",
            ]
            try:
                completed = self._run_merge(command, deadline)
            except (OSError, subprocess.TimeoutExpired):
                result["status"] = "merge_execution_failed"
                return result
            finally:
                try:
                    subprocess.run(
                        ["docker", "rm", "-f", name],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=15, check=False,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if completed.returncode != 0:
                result["status"] = "merge_execution_failed"
                return result
            if time.monotonic() >= deadline:
                result["status"] = "merge_verification_timeout"
                return result
            try:
                selected: list[Path] = []
                for path in merged.iterdir():
                    self._check_cancel()
                    if time.monotonic() >= deadline:
                        raise TimeoutError("corpus merge verification timed out")
                    selected.append(path)
                    if len(selected) > len(snapshot):
                        result["status"] = "merge_output_invalid"
                        return result
                selected.sort()
                if not selected or any(path.is_symlink() or not path.is_file() for path in selected):
                    result["status"] = "merge_output_invalid"
                    return result
                selected_bytes = 0
                for path in selected:
                    self._check_cancel()
                    if time.monotonic() >= deadline:
                        raise TimeoutError("corpus merge verification timed out")
                    selected_bytes += path.stat().st_size
                if selected_bytes > total_bytes:
                    result["status"] = "merge_output_invalid"
                    return result
                selected_hashes = {
                    self._file_sha256(path, deadline, self.cancel_event)
                    for path in selected
                }
                original = [
                    (path, stat, self._file_sha256(path, deadline, self.cancel_event))
                    for path, stat in snapshot
                ]
            except TimeoutError:
                result["status"] = "merge_verification_timeout"
                return result
            except OSError:
                result["status"] = "merge_output_invalid"
                return result
            if not selected_hashes.issubset({digest for _, _, digest in original}):
                result["status"] = "merge_output_invalid"
                return result
            kept: set[str] = set()
            redundant: list[tuple[Path, os.stat_result]] = []
            kept_bytes = 0
            for path, stat, digest in original:
                self._check_cancel()
                if time.monotonic() >= deadline:
                    result["status"] = "merge_verification_timeout"
                    return result
                if digest in selected_hashes and digest not in kept:
                    kept.add(digest)
                    kept_bytes += stat.st_size
                else:
                    redundant.append((path, stat))
            if len(kept) > max_files or kept_bytes > max_bytes:
                result["status"] = "merge_still_over_limit"
                return result
            # Keep original filenames. Only unlink snapshot files which still have
            # the exact inode, size and mtime that libFuzzer was given.
            current_state = self._read_state(job_dir)
            if current_state.get("active_fuzz_container") or current_state.get("active_afl_container"):
                result["status"] = "active_fuzz_deferred"
                return result
            for path, previous in redundant:
                self._check_cancel()
                if time.monotonic() > deadline:
                    result["status"] = "merge_verification_timeout"
                    break
                try:
                    current = path.stat()
                    if (current.st_ino, current.st_size, current.st_mtime_ns) != (
                        previous.st_ino, previous.st_size, previous.st_mtime_ns
                    ):
                        continue
                    path.unlink()
                    result["removed_files"] += 1
                    result["removed_bytes"] += previous.st_size
                except OSError:
                    continue
            if result["status"] != "merge_verification_timeout":
                result["status"] = "merged"
            try:
                remaining: list[Path] = []
                for path in corpus.iterdir():
                    self._check_cancel()
                    if time.monotonic() >= deadline:
                        raise TimeoutError("corpus merge verification timed out")
                    remaining.append(path)
                    if len(remaining) > max_files:
                        break
                remaining_bytes = 0
                unsafe = False
                for path in remaining:
                    self._check_cancel()
                    if time.monotonic() >= deadline:
                        raise TimeoutError("corpus merge verification timed out")
                    if path.is_symlink() or not path.is_file():
                        unsafe = True
                        break
                    remaining_bytes += path.stat().st_size
                result["over_limit"] = (
                    len(remaining) > max_files or unsafe or remaining_bytes > max_bytes
                )
            except TimeoutError:
                result["status"] = "merge_verification_timeout"
                result["over_limit"] = True
            except OSError:
                result["over_limit"] = True
        finally:
            try:
                temporary.cleanup()
            except OSError:
                result["cleanup_failed"] = True
                result["over_limit"] = True
        return result

    @staticmethod
    def _compaction_result(corpus: Path, status: str) -> dict[str, Any]:
        return {
            "target": corpus.name, "status": status, "over_limit": True,
            "removed_files": 0, "removed_bytes": 0,
        }

    def _run_merge(
        self, command: list[str], deadline: float
    ) -> subprocess.CompletedProcess[bytes]:
        if self.cancel_event is None:
            return subprocess.run(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=max(0.001, deadline - time.monotonic()), check=False,
            )
        self._check_cancel()
        process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        try:
            while True:
                self._check_cancel()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, MERGE_TIMEOUT_SECONDS)
                try:
                    return subprocess.CompletedProcess(
                        command, process.wait(timeout=min(0.5, remaining))
                    )
                except subprocess.TimeoutExpired:
                    continue
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)

    @staticmethod
    def _file_sha256(
        path: Path, deadline: float,
        cancel_event: threading.Event | None = None,
    ) -> str:
        if time.monotonic() >= deadline:
            raise TimeoutError("corpus merge verification exceeded its time limit")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                _check_cancel(cancel_event)
                if time.monotonic() > deadline:
                    raise TimeoutError("corpus merge verification exceeded its time limit")
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _prune_files(
        root: Path, max_files: int, max_bytes: int | None,
        *, cancel_event: threading.Event | None = None,
    ) -> tuple[int, int]:
        if root.is_symlink() or not root.is_dir():
            return 0, 0
        files = []
        for path in root.rglob("*"):
            _check_cancel(cancel_event)
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
            _check_cancel(cancel_event)
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
        self._check_cancel()
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
            self._check_cancel()
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
