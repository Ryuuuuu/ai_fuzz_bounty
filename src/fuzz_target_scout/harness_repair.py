"""Operator-reviewed replacement of one generated native fuzz harness."""

from __future__ import annotations

import copy
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from typing import Any

from .harness_generation import validate_generated_harness
from .pipeline import PipelineError, utc_now
from .pipeline_runner import JOB_ID_PATTERN
from .quartet_gate import probe_crash_diagnostics
from .retarget import (
    ARCHIVE_DIRECTORIES,
    PRESERVED_ARTIFACTS,
    _acquire_lock,
    _check_build_source,
    _read_json,
    _write_json,
)

MAX_CARRY_FILES = 20_000
MAX_CARRY_BYTES = 1024 ** 3
MAX_CARRY_FILE_BYTES = 1024 ** 2


def _regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise PipelineError(f"{label} is missing, is not a regular file, or is a symlink")


def _check_labeled_containers() -> None:
    """Refuse every pipeline-labeled container, regardless of job or status."""
    try:
        result = subprocess.run(
            [
                "docker", "ps", "--all", "--filter", "label=fuzz-target-scout=true",
                "--format", "{{.Names}}",
            ],
            capture_output=True, text=True, encoding="utf-8",
            timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PipelineError(f"cannot verify Docker containers: {exc}") from exc
    if result.returncode:
        raise PipelineError(
            "cannot verify Docker containers: "
            + (result.stderr or result.stdout).strip()[:300]
        )
    names = [name for name in result.stdout.splitlines() if name]
    if names:
        raise PipelineError(
            "pipeline has a labeled Docker container: " + ", ".join(names[:3])
        )


def _write_harness(path: Path, code: str) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    ) as output:
        temporary = Path(output.name)
        output.write(code)
    try:
        temporary.chmod(0o644)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _candidate_for_repair(
    generic: dict[str, Any], build_source: Path
) -> dict[str, Any]:
    candidate = generic.get("candidate")
    if not isinstance(candidate, dict):
        raise PipelineError("generated harness has no recorded API candidate")
    signature = str(candidate.get("signature") or "").strip()
    relative = PurePosixPath(str(candidate.get("file") or ""))
    if (
        not signature
        or "LLVMFuzzerTestOneInput" in signature
        or relative.is_absolute()
        or not relative.parts
        or "." in relative.parts
        or ".." in relative.parts
    ):
        raise PipelineError("generated harness has no usable recorded API candidate")
    candidate_file = build_source.joinpath(*relative.parts)
    _regular_file(candidate_file, "recorded API candidate source")
    if not candidate_file.resolve().is_relative_to(build_source.resolve()):
        raise PipelineError("recorded API candidate escapes pinned build-source")
    return candidate


def _check_finding_evidence(artifacts: Path, state: dict[str, Any]) -> None:
    if state.get("finding_source") or state.get("triage_artifact"):
        raise PipelineError("job has pending finding evidence; harness repair refused")
    for name in (
        "validation-handoff.json", "validation-agent-report.json",
        "poc-manifest.json", "bug-bounty-report-draft.md",
    ):
        if (artifacts / name).exists() or (artifacts / name).is_symlink():
            raise PipelineError(f"job has finding evidence ({name}); harness repair refused")
    summaries = [artifacts / "triage-summary.json"]
    triage_history = artifacts / "triage-history"
    if triage_history.is_symlink():
        raise PipelineError("triage history is a symlink; harness repair refused")
    if triage_history.is_dir():
        summaries.extend(triage_history.glob("*.json"))
    for triage in summaries:
        if not triage.exists():
            continue
        summary = _read_json(triage)
        if (
            int(summary.get("validated_group_count") or 0) > 0
            or summary.get("report_draft")
            or any(group.get("reproduced") for group in summary.get("groups") or [])
        ):
            raise PipelineError("job has reproduced finding evidence; harness repair refused")
    for name in ("validation", "poc"):
        directory = artifacts.parent / name
        if directory.is_symlink():
            raise PipelineError(f"job {name} path is a symlink; harness repair refused")
        if directory.is_dir() and any(directory.iterdir()):
            raise PipelineError(f"job has {name} finding evidence; harness repair refused")


def _corpus_sources(corpus: Path) -> tuple[list[Path], int, int]:
    """Choose prior seeds without following links or copying crash inputs."""
    if not corpus.exists():
        return [], 0, 0
    if corpus.is_symlink() or not corpus.is_dir():
        raise PipelineError("corpus is not a regular directory")
    seeds: list[Path] = []
    skipped = 0
    copied_bytes = 0
    for root, directories, files in os.walk(corpus, followlinks=False):
        directories.sort()
        root_path = Path(root)
        if any((root_path / name).is_symlink() for name in directories + files):
            raise PipelineError("corpus contains a symlink; harness repair refused")
        for name in sorted(files):
            path = root_path / name
            _regular_file(path, "corpus seed")
            size = path.stat().st_size
            if (
                size > MAX_CARRY_FILE_BYTES
                or len(seeds) >= MAX_CARRY_FILES
                or copied_bytes + size > MAX_CARRY_BYTES
            ):
                skipped += 1
                continue
            seeds.append(path.relative_to(corpus))
            copied_bytes += size
    return seeds, skipped, copied_bytes


def repair_native_harness(
    config: dict[str, Any],
    job_id: str,
    file: str | Path,
    rationale: str,
    *,
    dry_run: bool = False,
    seed_files: tuple[str | Path, ...] = (),
) -> dict[str, Any]:
    """Archive the prior attempt and queue a clean native build of reviewed code."""
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise PipelineError("invalid repair job id")
    rationale = rationale.strip()
    if not rationale:
        raise PipelineError("harness repair rationale is required")
    replacement = Path(file).expanduser()
    _regular_file(replacement, "replacement harness")
    try:
        code = replacement.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PipelineError(f"could not read replacement harness: {exc}") from exc
    extra_seeds: list[tuple[str, bytes]] = []
    for item in seed_files:
        path = Path(item).expanduser()
        _regular_file(path, "seed file")
        if path.stat().st_size > 10_000_000:
            raise PipelineError(f"seed file is too large: {path}")
        data = path.read_bytes()
        extra_seeds.append((str(path), data))

    runs_root = Path(config["pipeline"]["runs_path"])
    job_dir = runs_root / job_id
    if (
        runs_root.is_symlink() or job_dir.is_symlink() or not job_dir.is_dir()
        or job_dir.resolve().parent != runs_root.resolve()
    ):
        raise PipelineError(f"job directory was not found: {job_dir}")
    service_lock = Path(config["agent"]["state_path"]).parent / ".central-agent.lock"
    worker_lock = runs_root / ".pipeline-worker.lock"
    with ExitStack() as stack:
        _acquire_lock(stack, service_lock, "central fuzz service")
        _acquire_lock(stack, worker_lock, "fuzz pipeline worker")
        _check_labeled_containers()
        job = _read_json(job_dir / "job.json")
        state_path = job_dir / "state.json"
        state = _read_json(state_path)
        if (job.get("route") or {}).get("name") != "native_generated":
            raise PipelineError("harness repair supports native_generated jobs only")
        if state.get("job_id") != job_id or job.get("job_id") != job_id:
            raise PipelineError("job identity does not match directory")
        if state.get("status") not in {
            "quartet_review_required", "skipped_after_recovery",
        }:
            raise PipelineError("job is not awaiting operator harness review")
        artifacts = job_dir / "artifacts"
        if artifacts.is_symlink() or not artifacts.is_dir():
            raise PipelineError("job artifacts directory is missing or a symlink")
        _check_finding_evidence(artifacts, state)
        _check_build_source(job_dir, job)
        generic_path = artifacts / "generic-integration.json"
        manifest_path = artifacts / "integration-manifest.json"
        _regular_file(generic_path, "generated integration metadata")
        _regular_file(manifest_path, "integration manifest")
        generic = _read_json(generic_path)
        manifest = _read_json(manifest_path)
        if manifest.get("route") != "native_generated":
            raise PipelineError("integration manifest is not native_generated")
        if str(manifest.get("target_commit") or "").casefold() != str(
            (job.get("source") or {}).get("commit") or ""
        ).casefold():
            raise PipelineError("integration manifest is not pinned to the job commit")
        project_dir = job_dir / "integration" / "native"
        if (
            (job_dir / "integration").is_symlink()
            or project_dir.is_symlink() or not project_dir.is_dir()
            or Path(str(manifest.get("native_project_directory") or "")).resolve()
            != project_dir.resolve()
        ):
            raise PipelineError("native project directory does not match the job")
        harness = project_dir / "generic_harness.cc"
        _regular_file(harness, "current native harness")
        old_code = harness.read_bytes()
        old_sha256 = hashlib.sha256(old_code).hexdigest()
        if generic.get("harness_sha256") != old_sha256:
            raise PipelineError("current harness differs from generated integration metadata")
        old_manifest_sha256 = (
            (manifest.get("integration_file_sha256") or {}).get("generic_harness.cc")
        )
        candidate = _candidate_for_repair(generic, job_dir / "build-source")
        validation = validate_generated_harness(code, candidate)
        if validation["sha256"] == old_sha256:
            raise PipelineError("replacement harness is identical to the current harness")
        probe_path = artifacts / "probe-run.json"
        if probe_path.exists() or probe_path.is_symlink():
            _regular_file(probe_path, "probe result")
            probe = _read_json(probe_path)
        else:
            probe = {}
        crash_diagnostics = probe_crash_diagnostics(job_dir, probe)
        classification = str(crash_diagnostics.get("kind") or "untriaged")
        crashes = job_dir / "crashes"
        if crashes.is_symlink():
            raise PipelineError("crashes path is a symlink; harness repair refused")
        physical_crashes = (
            crashes.is_dir()
            and any(path.is_file() or path.is_symlink() for path in crashes.rglob("*"))
        )
        crash_present = bool(
            probe.get("crash_files")
            or probe.get("status") == "sanitizer_finding"
            or physical_crashes
        )
        if crash_present and classification == "none":
            classification = "untriaged"
            crash_diagnostics = {"kind": classification, "lines": []}
        if crash_present and classification != "uncaught_cpp_exception":
            raise PipelineError(
                f"{classification} crash requires finding review; harness repair refused"
            )
        corpus_sources, archived_only_seeds, carried_bytes = _corpus_sources(
            job_dir / "corpus"
        )
        history = artifacts / "history"
        if history.is_symlink():
            raise PipelineError("job history path is a symlink")
        preserved = PRESERVED_ARTIFACTS | {
            "integration-support.json", "harness-exclusions.json",
        }
        archive_items = [
            (path, Path("artifacts") / path.name)
            for path in sorted(artifacts.iterdir())
            if path.name not in preserved
        ]
        archive_items += [
            (job_dir / name, Path(name)) for name in ARCHIVE_DIRECTORIES
            if name != "integration"
            and ((job_dir / name).exists() or (job_dir / name).is_symlink())
        ]
        if any(source.is_symlink() for source, _ in archive_items):
            raise PipelineError("harness repair refuses symlinked evidence paths")
        archive = history / f"operator-harness-repair-{time.time_ns()}"
        record = {
            "schema_version": 1, "created_at": utc_now(), "job_id": job_id,
            "kind": "operator_harness_repair", "rationale": rationale[:1200],
            "source_file": str(replacement.resolve()),
            "old_harness_sha256": old_sha256,
            "old_manifest_harness_sha256": old_manifest_sha256,
            "old_manifest_harness_hash_stale": old_manifest_sha256 != old_sha256,
            "new_harness_sha256": validation["sha256"],
            "old_crash_classification": classification,
            "old_crash_diagnostics": crash_diagnostics,
            "previous_stage": state.get("stage"),
            "previous_status": state.get("status"),
            "archive": archive.relative_to(job_dir).as_posix(),
            "archived_paths": [target.as_posix() for _, target in archive_items]
            + ["state.json", "integration/native/generic_harness.cc"],
            "carried_corpus_files": len(corpus_sources),
            "carried_corpus_bytes": carried_bytes,
            "archive_only_corpus_files": archived_only_seeds,
            "extra_seed_files": [name for name, _ in extra_seeds],
            "validation": validation,
            "next_stage": "build", "next_status": "integrated",
        }
        if dry_run:
            return {**record, "dry_run": True}

        archive.mkdir(parents=True, exist_ok=False)
        _write_json(archive / "state.json", state)
        old_harness_archive = archive / "integration" / "native" / "generic_harness.cc"
        old_harness_archive.parent.mkdir(parents=True, exist_ok=True)
        old_harness_archive.write_bytes(old_code)
        moved: list[tuple[Path, Path]] = []
        written: list[Path] = []
        created_directories: list[Path] = []
        try:
            for source, relative in archive_items:
                target = archive / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                source.replace(target)
                moved.append((source, target))
            _write_json(archive / "repair.json", record)
            _write_harness(harness, code)
            updated_generic = copy.deepcopy(generic)
            updated_generic["harness_origin"] = "operator_reviewed_repair"
            updated_generic["harness_sha256"] = validation["sha256"]
            updated_generic.setdefault("repair_attempts", []).append({
                "kind": "operator_reviewed_replacement",
                "created_at": record["created_at"],
                "rationale": record["rationale"],
                "validation": validation,
                "archive": record["archive"],
            })
            _write_json(generic_path, updated_generic)
            written.append(generic_path)
            updated_manifest = copy.deepcopy(manifest)
            updated_manifest.setdefault("integration_file_sha256", {})[
                "generic_harness.cc"
            ] = validation["sha256"]
            updated_manifest.pop("runner_image", None)
            updated_manifest.pop("runner_image_arch", None)
            _write_json(manifest_path, updated_manifest)
            written.append(manifest_path)
            repair_path = artifacts / "operator-harness-repair.json"
            _write_json(repair_path, record)
            written.append(repair_path)
            for name in ("corpus", "crashes", "logs", "runtime-out"):
                path = job_dir / name
                path.mkdir(exist_ok=False)
                created_directories.append(path)
            for relative in corpus_sources:
                prior = archive / "corpus" / relative
                destination = job_dir / "corpus" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(prior, destination)
            seed_dir = job_dir / "corpus" / "generic_fuzzer"
            for _, data in extra_seeds:
                seed_dir.mkdir(parents=True, exist_ok=True)
                (seed_dir / hashlib.sha256(data).hexdigest()).write_bytes(data)
            next_state = {
                "schema_version": state.get("schema_version", 2),
                "job_id": job_id,
                "created_at": state.get("created_at") or job.get("created_at"),
                "updated_at": utc_now(),
                "status": "integrated", "stage": "build",
                "attempts": {
                    "operator_harness_repair": int(
                        (state.get("attempts") or {}).get("operator_harness_repair", 0)
                    ) + 1,
                },
                "last_error": None,
            }
            _write_json(state_path, next_state)
        except Exception:
            harness.write_bytes(old_code)
            for path in written:
                path.unlink(missing_ok=True)
            for path in reversed(created_directories):
                shutil.rmtree(path)
            for source, target in reversed(moved):
                target.replace(source)
            raise
        return {**record, "dry_run": False}
