"""Operator-controlled reset of a generated native harness within one job."""

from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from .pipeline import PipelineError, utc_now
from .pipeline_runner import JOB_ID_PATTERN


ARCHIVE_DIRECTORIES = (
    "integration", "build-output", "native-work", "native-out",
    "runtime-out", "corpus", "crashes", "logs", "validation", "poc",
)
PRESERVED_ARTIFACTS = {
    "history", "source-checkout.json", "toolchain.json",
    "authorization-recheck.json", "central-recovery.json",
}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PipelineError(f"expected an object in {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    ) as output:
        temporary = Path(output.name)
        json.dump(value, output, indent=2, ensure_ascii=False, sort_keys=True)
        output.write("\n")
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _git_output(path: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), *args], capture_output=True,
            text=True, encoding="utf-8", timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PipelineError(f"could not verify pinned build worktree: {exc}") from exc
    if result.returncode:
        raise PipelineError(
            f"could not verify pinned build worktree: {(result.stderr or result.stdout).strip()[:300]}"
        )
    return result.stdout.strip()


def _check_build_source(job_dir: Path, job: dict[str, Any]) -> None:
    build_source = job_dir / "build-source"
    if build_source.is_symlink() or not build_source.is_dir():
        raise PipelineError("pinned build-source worktree is missing or a symlink")
    commit = str((job.get("source") or {}).get("commit") or "")
    if not commit or _git_output(build_source, "rev-parse", "HEAD").casefold() != commit.casefold():
        raise PipelineError("pinned build-source worktree is at the wrong commit")
    if _git_output(build_source, "status", "--porcelain", "--untracked-files=normal"):
        raise PipelineError("pinned build-source worktree has uncommitted changes")


def _acquire_lock(stack: ExitStack, path: Path, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = stack.enter_context(path.open("a+", encoding="utf-8"))
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise PipelineError(f"{label} is active; stop it before retargeting") from exc


def _check_running_container(job_id: str) -> None:
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "label=fuzz-target-scout=true", "--format", "{{.Names}}"],
            capture_output=True, text=True, encoding="utf-8",
            timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PipelineError(f"cannot verify running Docker containers: {exc}") from exc
    if result.returncode:
        raise PipelineError(
            "cannot verify running Docker containers: "
            + (result.stderr or result.stdout).strip()[:300]
        )
    matches = [name for name in result.stdout.splitlines() if name]
    if matches:
        raise PipelineError(
            f"pipeline has a running Docker container: {', '.join(matches[:3])}"
        )


def _check_finding_evidence(job_dir: Path, state: dict[str, Any]) -> None:
    if state.get("finding_source") or state.get("triage_artifact"):
        raise PipelineError("job has pending crash or finding evidence; retarget refused")
    if state.get("status") in {
        "triage_pending", "triage_review_required", "validation_pending",
        "validation_running", "validation_review_required", "ready_for_human",
    }:
        raise PipelineError("job has pending or verified finding review; retarget refused")
    artifacts = job_dir / "artifacts"
    for name in (
        "validation-handoff.json", "validation-agent-report.json",
        "poc-manifest.json", "bug-bounty-report-draft.md",
    ):
        if (artifacts / name).exists() or (artifacts / name).is_symlink():
            raise PipelineError(f"job has finding evidence ({name}); retarget refused")
    for name in ("crashes", "poc", "validation"):
        directory = job_dir / name
        if directory.is_symlink():
            raise PipelineError(f"job {name} path is a symlink; retarget refused")
        if directory.is_dir() and any(path.is_file() or path.is_symlink() for path in directory.rglob("*")):
            raise PipelineError(f"job has {name} evidence; retarget refused")
    for name in ("probe-run.json", "fuzz-run.json", "afl-cmplog-run.json"):
        path = artifacts / name
        if path.is_file() and _read_json(path).get("crash_files"):
            raise PipelineError(f"job has crash evidence ({name}); retarget refused")
    summaries = [artifacts / "triage-summary.json"]
    history = artifacts / "triage-history"
    if history.is_symlink():
        raise PipelineError("triage history is a symlink; retarget refused")
    if history.is_dir():
        summaries.extend(history.glob("*.json"))
    for path in summaries:
        if not path.exists():
            continue
        summary = _read_json(path)
        if (int(summary.get("validated_group_count") or 0) > 0
                or summary.get("report_draft")
                or any(group.get("reproduced") for group in summary.get("groups") or [])):
            raise PipelineError("job has reproduced finding or report evidence; retarget refused")


def _has_failed_generation_evidence(artifacts: Path) -> bool:
    generation = artifacts / "generic-integration-generation"
    if generation.is_symlink() or not generation.is_dir():
        return False
    prompt = generation / "prompt.txt"
    if prompt.is_symlink() or not prompt.is_file():
        return False
    return any(
        path.is_file() and not path.is_symlink()
        for path in (generation / "adapter.log", generation / "01.rawoutput")
    )


def retarget_native_job(
    config: dict[str, Any], job_id: str, rationale: str, *, dry_run: bool = False,
) -> dict[str, Any]:
    """Archive one native harness attempt and queue a fresh integration in the same job.

    Both service locks are held across the Docker check and filesystem changes.
    Standalone stage commands do not share these locks and must not run concurrently.
    """
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise PipelineError("invalid retarget job id")
    rationale = rationale.strip()
    if not rationale:
        raise PipelineError("retarget rationale is required")
    runs_root = Path(config["pipeline"]["runs_path"])
    job_dir = runs_root / job_id
    if (runs_root.is_symlink() or job_dir.is_symlink() or not job_dir.is_dir()
            or job_dir.resolve().parent != runs_root.resolve()):
        raise PipelineError(f"job directory was not found: {job_dir}")
    service_lock = Path(config["agent"]["state_path"]).parent / ".central-agent.lock"
    worker_lock = runs_root / ".pipeline-worker.lock"
    with ExitStack() as stack:
        _acquire_lock(stack, service_lock, "central fuzz service")
        _acquire_lock(stack, worker_lock, "fuzz pipeline worker")
        _check_running_container(job_id)
        job = _read_json(job_dir / "job.json")
        state_path = job_dir / "state.json"
        state = _read_json(state_path)
        if (job.get("route") or {}).get("name") != "native_generated":
            raise PipelineError("retarget supports native_generated jobs only")
        if state.get("job_id") != job_id:
            raise PipelineError("job state identity does not match directory")
        artifacts = job_dir / "artifacts"
        if artifacts.is_symlink() or not artifacts.is_dir():
            raise PipelineError("job artifacts directory is missing or a symlink")
        generic_path = artifacts / "generic-integration.json"
        if generic_path.is_symlink():
            raise PipelineError("job has no generated harness integration to retarget")
        if generic_path.is_file():
            generic = _read_json(generic_path)
        elif (
            not generic_path.exists()
            and state.get("stage") == "complete"
            and state.get("status") == "skipped_after_recovery"
            and state.get("last_error")
            and _has_failed_generation_evidence(artifacts)
        ):
            generic = {}
        else:
            raise PipelineError("job has no generated harness integration or failed generation evidence to retarget")
        _check_finding_evidence(job_dir, state)
        _check_build_source(job_dir, job)
        archive_items = [
            (path, Path("artifacts") / path.name)
            for path in sorted(artifacts.iterdir())
            if path.name not in PRESERVED_ARTIFACTS
        ]
        archive_items += [
            (job_dir / name, Path(name)) for name in ARCHIVE_DIRECTORIES
            if (job_dir / name).exists() or (job_dir / name).is_symlink()
        ]
        if any(source.is_symlink() for source, _ in archive_items):
            raise PipelineError("retarget refuses symlinked evidence paths")
        history = artifacts / "history"
        if history.is_symlink():
            raise PipelineError("job history path is a symlink")
        archive = history / f"operator-retarget-{time.time_ns()}"
        candidate = generic.get("candidate") or {}
        origin = str(generic.get("harness_origin") or "")
        old_exclusions = (
            _read_json(artifacts / "harness-exclusions.json")
            if (artifacts / "harness-exclusions.json").is_file() else {}
        )
        paths = [str(value) for value in old_exclusions.get("paths") or [] if isinstance(value, str)]
        if origin.startswith("existing:") and candidate.get("file"):
            paths.append(str(candidate["file"]))
        candidate_ids = [
            str(value) for value in old_exclusions.get("candidate_ids") or []
            if isinstance(value, str)
        ]
        if candidate.get("id"):
            candidate_ids.append(str(candidate["id"]))
        exclusions = {
            "schema_version": 1, "updated_at": utc_now(),
            "paths": list(dict.fromkeys(paths))[-20:],
            "candidate_ids": list(dict.fromkeys(candidate_ids))[-20:],
        }
        record = {
            "schema_version": 1, "created_at": utc_now(), "job_id": job_id,
            "kind": "operator_retarget", "rationale": rationale[:1200],
            "previous_stage": state.get("stage"),
            "previous_status": state.get("status"),
            "previous_candidate": candidate,
            "previous_harness_origin": origin,
            "archive": archive.relative_to(job_dir).as_posix(),
            "archived_paths": [target.as_posix() for _, target in archive_items],
            "next_stage": "integration", "next_status": "prepared",
        }
        if dry_run:
            return {**record, "dry_run": True}

        archive.mkdir(parents=True, exist_ok=False)
        _write_json(archive / "state.json", state)
        moved: list[tuple[Path, Path]] = []
        new_metadata: list[Path] = []
        fresh_dirs: list[Path] = []
        try:
            for source, relative in archive_items:
                target = archive / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                source.replace(target)
                moved.append((source, target))
            _write_json(archive / "retarget.json", record)
            for name in ("integration", "corpus", "crashes", "logs", "validation"):
                path = job_dir / name
                if not path.exists():
                    path.mkdir()
                    fresh_dirs.append(path)
            exclusion_path = artifacts / "harness-exclusions.json"
            _write_json(exclusion_path, exclusions)
            new_metadata.append(exclusion_path)
            retarget_path = artifacts / "retarget.json"
            _write_json(retarget_path, record)
            new_metadata.append(retarget_path)
            next_state = {
                "schema_version": state.get("schema_version", 2),
                "job_id": job_id, "created_at": state.get("created_at") or job.get("created_at"),
                "updated_at": utc_now(), "status": "prepared", "stage": "integration",
                "attempts": {"retargets": int((state.get("attempts") or {}).get("retargets", 0)) + 1},
                "last_error": None,
            }
            _write_json(state_path, next_state)
        except Exception:
            for path in new_metadata:
                path.unlink(missing_ok=True)
            for path in reversed(fresh_dirs):
                path.rmdir()
            for source, target in reversed(moved):
                target.replace(source)
            raise
        return {**record, "dry_run": False}
