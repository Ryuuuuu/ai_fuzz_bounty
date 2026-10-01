from __future__ import annotations

import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .architecture import resolve_host_architecture


COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{7,64}$")
CPP_LANGUAGES = {"c", "c++", "cpp"}
REPOSITORY_FAILURE_STATUSES = {
    "skipped_after_recovery",
    "unsupported_integration",
}
OFFLINE_DEPENDENCY_REASON = "offline_external_dependency"
REPOSITORY_SUCCESS_STATUSES = {"exhausted", "ready_for_human"}

_LIVE_WORKER_LIMIT = 64
_LIVE_LOG_TAIL_BYTES = 64 * 1024
_LIVE_FILE_LIMIT = 200_000
_LIVE_LOG_LINE = re.compile(
    rb"^#\d+\s+\S+.*?\bcov:\s*(\d+)\s+ft:\s*(\d+)"
    rb".*?\bexec/s:\s*(\d+)(?:\s|$)"
)


class PipelineError(RuntimeError):
    pass


class PipelineInterrupted(PipelineError):
    """A resumable operator or service shutdown, not a pipeline failure."""


class UnsupportedIntegrationError(PipelineError):
    """The target is valid but has no safely reusable build integration."""


class OfflineDependencyError(UnsupportedIntegrationError):
    """The isolated build requires an unavailable external dependency."""


@dataclass(slots=True)
class PlanSummary:
    created: int
    existing: int
    skipped: int
    skip_reasons: dict[str, int]
    job_ids: list[str]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_jsonl(path: str | Path) -> Iterable[dict[str, Any]]:
    source = Path(path)
    if not source.is_file():
        raise PipelineError(f"candidate export was not found: {source}")
    with source.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PipelineError(
                    f"invalid JSON on {source}:{line_number}: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise PipelineError(f"candidate on {source}:{line_number} is not an object")
            yield value


def prepare_jobs(
    candidates: Iterable[dict[str, Any]],
    runs_root: str | Path,
    pipeline_config: dict[str, Any],
    toolchain_lock: dict[str, Any],
    support_index: dict[str, dict[str, str]] | None = None,
    limit: int | None = None,
) -> PlanSummary:
    root = Path(runs_root)
    root.mkdir(parents=True, exist_ok=True)
    created = 0
    existing = 0
    reasons: Counter[str] = Counter()
    job_ids: list[str] = []
    selected_repositories = _selected_repositories(root)

    queued = list(candidates)
    architecture_config = pipeline_config.get("architecture")
    host_arch = resolve_host_architecture(architecture_config or {})
    oss_fuzz_native = architecture_config is None or host_arch == "x86_64"
    queued.sort(
        key=lambda item: (
            bool(
                support_index is not None
                and oss_fuzz_native
                and str(item.get("repository") or "").casefold()
                not in support_index
            ),
            -float((item.get("assessment") or {}).get("fuzz_score") or 0),
            str(item.get("repository") or "").casefold(),
        )
    )
    for candidate in queued:
        if limit is not None and created + existing >= limit:
            break
        work_order, reason = make_work_order(
            candidate, pipeline_config, toolchain_lock, support_index
        )
        if work_order is None:
            reasons[reason] += 1
            continue
        job_id = work_order["job_id"]
        job_dir = root / job_id
        if (job_dir / "job.json").is_file():
            try:
                previous = json.loads((job_dir / "state.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                previous = {}
            if previous.get("stage") == "complete":
                reasons["historical_exact_commit"] += 1
                continue
            existing += 1
            job_ids.append(job_id)
            continue
        repository = str((work_order.get("source") or {}).get("repository") or "")
        if repository.strip().casefold() in selected_repositories:
            reasons["repository_previously_selected"] += 1
            continue
        job_dir.mkdir(parents=False, exist_ok=False)
        for name in (
            "artifacts",
            "corpus",
            "crashes",
            "integration",
            "logs",
            "validation",
        ):
            (job_dir / name).mkdir()
        _write_json(job_dir / "job.json", work_order)
        _write_json(
            job_dir / "state.json",
            {
                "schema_version": 2,
                "job_id": job_id,
                "status": "queued",
                "stage": "policy_recheck",
                "created_at": work_order["created_at"],
                "updated_at": work_order["created_at"],
                "attempts": {},
                "last_error": None,
            },
        )
        selected_repositories.add(repository.strip().casefold())
        created += 1
        job_ids.append(job_id)
    return PlanSummary(
        created=created,
        existing=existing,
        skipped=sum(reasons.values()),
        skip_reasons=dict(sorted(reasons.items())),
        job_ids=job_ids,
    )


def _selected_repositories(runs_root: Path) -> set[str]:
    """Return every repository with a saved job, regardless of commit or outcome."""
    repositories: set[str] = set()
    if not runs_root.is_dir() or runs_root.is_symlink():
        return repositories
    for job_path in runs_root.glob("*/job.json"):
        try:
            job = json.loads(job_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(job, dict):
            continue
        source = job.get("source")
        if not isinstance(source, dict):
            continue
        repository = str(source.get("repository") or "").strip().casefold()
        if repository:
            repositories.add(repository)
    return repositories


def repository_discovery_exclusions(
    runs_root: str | Path, pipeline_config: dict[str, Any]
) -> set[str]:
    """Skip any previously selected repository before GitHub detail lookups."""
    root = Path(runs_root)
    return (
        _selected_repositories(root)
        | set(repository_failure_cooldowns(root, pipeline_config))
        | set(repository_success_cooldowns(root, pipeline_config))
    )


def repository_failure_cooldowns(
    runs_root: str | Path,
    pipeline_config: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Return repositories whose latest completed jobs repeatedly failed.

    A successful completed run resets the consecutive failure sequence. Jobs
    skipped because the circuit was already open do not extend the cooldown.
    """
    threshold = max(
        0, int(pipeline_config.get("repository_failure_threshold", 2))
    )
    cooldown_hours = max(
        0, int(pipeline_config.get("repository_failure_cooldown_hours", 168))
    )
    if threshold == 0 or cooldown_hours == 0:
        return {}
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    histories: dict[str, list[tuple[datetime, str, str, str]]] = {}
    root = Path(runs_root)
    if not root.is_dir() or root.is_symlink():
        return {}
    for job_path in root.glob("*/job.json"):
        state_path = job_path.with_name("state.json")
        try:
            job = json.loads(job_path.read_text(encoding="utf-8"))
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if state.get("stage") != "complete":
            continue
        repository = str((job.get("source") or {}).get("repository") or "")
        if not repository:
            continue
        observed = _pipeline_timestamp(str(state.get("updated_at") or ""))
        if observed is None:
            try:
                observed = datetime.fromtimestamp(
                    state_path.stat().st_mtime, timezone.utc
                )
            except OSError:
                continue
        histories.setdefault(repository.casefold(), []).append(
            (
                observed,
                str(state.get("status") or ""),
                job_path.parent.name,
                str(state.get("failure_reason") or ""),
            )
        )

    blocked: dict[str, dict[str, Any]] = {}
    for repository, entries in histories.items():
        consecutive: list[tuple[datetime, str, str, str]] = []
        for entry in sorted(entries, reverse=True):
            status = entry[1]
            if status in REPOSITORY_SUCCESS_STATUSES:
                break
            if status in REPOSITORY_FAILURE_STATUSES:
                consecutive.append(entry)
                continue
            if status == "skipped_repository_cooldown":
                continue
            break
        # An external download cannot succeed inside the networkless build.
        # Cool down that repository after the first such failure; keep the
        # configured threshold for ordinary failures.
        required = (
            1
            if consecutive and consecutive[0][3] == OFFLINE_DEPENDENCY_REASON
            else threshold
        )
        if len(consecutive) < required:
            continue
        newest = consecutive[0][0]
        age_seconds = max(0.0, (current - newest).total_seconds())
        if age_seconds >= cooldown_hours * 3600:
            continue
        blocked[repository] = {
            "failure_count": len(consecutive),
            "newest_failure_at": newest.isoformat(),
            "cooldown_until": datetime.fromtimestamp(
                newest.timestamp() + cooldown_hours * 3600, timezone.utc
            ).isoformat(),
            "job_ids": [entry[2] for entry in consecutive],
        }
    return blocked


def repository_success_cooldowns(
    runs_root: str | Path,
    pipeline_config: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Return recently completed repositories so scarce time reaches new code."""
    cooldown_hours = max(
        0, int(pipeline_config.get("repository_success_cooldown_hours", 0))
    )
    if cooldown_hours == 0:
        return {}
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    newest: dict[str, tuple[datetime, str]] = {}
    root = Path(runs_root)
    if not root.is_dir() or root.is_symlink():
        return {}
    for job_path in root.glob("*/job.json"):
        state_path = job_path.with_name("state.json")
        try:
            job = json.loads(job_path.read_text(encoding="utf-8"))
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (
            state.get("stage") != "complete"
            or state.get("status") not in REPOSITORY_SUCCESS_STATUSES
        ):
            continue
        repository = str((job.get("source") or {}).get("repository") or "").casefold()
        if not repository:
            continue
        observed = _pipeline_timestamp(str(state.get("updated_at") or ""))
        if observed is None:
            try:
                observed = datetime.fromtimestamp(
                    state_path.stat().st_mtime, timezone.utc
                )
            except OSError:
                continue
        if repository not in newest or observed > newest[repository][0]:
            newest[repository] = (observed, job_path.parent.name)
    blocked: dict[str, dict[str, Any]] = {}
    for repository, (observed, job_id) in newest.items():
        age_seconds = max(0.0, (current - observed).total_seconds())
        if age_seconds >= cooldown_hours * 3600:
            continue
        blocked[repository] = {
            "kind": "success",
            "newest_success_at": observed.isoformat(),
            "cooldown_until": datetime.fromtimestamp(
                observed.timestamp() + cooldown_hours * 3600, timezone.utc
            ).isoformat(),
            "job_ids": [job_id],
        }
    return blocked


def quarantine_previously_selected_jobs(runs_root: str | Path) -> list[str]:
    """Finish untouched duplicate jobs while preserving the first selected job."""
    root = Path(runs_root)
    if not root.is_dir() or root.is_symlink():
        return []
    by_repository: dict[str, list[tuple[Path, dict[str, Any], str]]] = {}
    for job_path in root.glob("*/job.json"):
        state_path = job_path.with_name("state.json")
        try:
            job = json.loads(job_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}
        if not isinstance(job, dict):
            continue
        if not isinstance(state, dict):
            state = {}
        source = job.get("source")
        if not isinstance(source, dict):
            continue
        repository = str(source.get("repository") or "").strip().casefold()
        if not repository:
            continue
        created_at = str(state.get("created_at") or job.get("created_at") or "")
        by_repository.setdefault(repository, []).append(
            (state_path, state, created_at)
        )

    quarantined: list[str] = []
    for entries in by_repository.values():
        if len(entries) < 2:
            continue
        ordered = sorted(entries, key=lambda item: (item[2], item[0].parent.name))
        started = [
            item for item in ordered
            if item[1].get("status") != "skipped_previously_attempted"
            and (
                item[1].get("stage") != "policy_recheck"
                or item[1].get("status") != "queued"
            )
        ]
        previous = (started or ordered)[0][0].parent.name
        for state_path, state, _ in ordered:
            if state_path.parent.name == previous:
                continue
            if state.get("stage") != "policy_recheck" or state.get("status") != "queued":
                continue
            state["stage"] = "complete"
            state["status"] = "skipped_previously_attempted"
            state["last_error"] = (
                f"repository was already selected in saved job {previous}"
            )
            state["previous_repository_job"] = previous
            state["updated_at"] = utc_now()
            _write_json(state_path, state)
            quarantined.append(state_path.parent.name)
    return sorted(quarantined)


def quarantine_repository_cooldown_jobs(
    runs_root: str | Path, pipeline_config: dict[str, Any]
) -> list[str]:
    """Finish untouched queued jobs for repositories with an open circuit."""
    root = Path(runs_root)
    failure_blocked = repository_failure_cooldowns(root, pipeline_config)
    success_blocked = repository_success_cooldowns(root, pipeline_config)
    quarantined: list[str] = []
    for state_path in root.glob("*/state.json"):
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            job = json.loads(
                state_path.with_name("job.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            continue
        if state.get("stage") != "policy_recheck" or state.get("status") != "queued":
            continue
        repository = str(
            (job.get("source") or {}).get("repository") or ""
        ).casefold()
        detail = failure_blocked.get(repository) or success_blocked.get(repository)
        if not detail:
            continue
        state["stage"] = "complete"
        state["status"] = "skipped_repository_cooldown"
        if detail.get("kind") == "success":
            state["last_error"] = (
                "repository recently completed; rotating to a different target"
            )
        else:
            state["last_error"] = (
                "repository circuit open after "
                f"{detail['failure_count']} consecutive failed jobs"
            )
        state["repository_cooldown"] = detail
        state["updated_at"] = utc_now()
        _write_json(state_path, state)
        quarantined.append(state_path.parent.name)
    return sorted(quarantined)


def _pipeline_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def make_work_order(
    candidate: dict[str, Any],
    pipeline_config: dict[str, Any],
    toolchain_lock: dict[str, Any],
    support_index: dict[str, dict[str, str]] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    policy = candidate.get("policy") or {}
    if policy.get("status") != "verified":
        return None, "policy_not_verified"
    if not policy.get("program_url") or not policy.get("security_url"):
        return None, "policy_evidence_incomplete"

    repository = str(candidate.get("repository") or "")
    if repository.count("/") != 1:
        return None, "invalid_repository"
    commit = str(candidate.get("commit") or "")
    if not COMMIT_PATTERN.fullmatch(commit):
        return None, "commit_not_pinned"

    language = str(candidate.get("language") or "")
    enabled = {str(value).casefold() for value in pipeline_config["languages"]}
    if language.casefold() not in enabled:
        return None, "language_not_enabled"

    assessment = candidate.get("assessment") or {}
    architecture_config = pipeline_config.get("architecture")
    host_arch = resolve_host_architecture(architecture_config or {})
    architecture = candidate.get("architecture") or {}
    if architecture_config and str(
        architecture_config.get("mode") or "native_only"
    ) == "native_only":
        if not bool(architecture.get("compatible")):
            return None, "host_architecture_not_verified"
        if str(architecture.get("host_arch") or "") != host_arch:
            return None, "candidate_architecture_mismatch"
    route, route_reason, tools, optional_tools = _route(
        language, assessment, toolchain_lock
    )
    if route is None:
        return None, route_reason
    support = None
    generic_build_signal = None
    if language.casefold() in CPP_LANGUAGES:
        oss_fuzz_native = architecture_config is None or host_arch == "x86_64"
        if not oss_fuzz_native:
            generic_build_signal = _generic_build_signal(assessment)
            if generic_build_signal is None:
                return None, "no_supported_native_build_signal"
            route = "native_generated"
            route_reason = (
                f"generate and build a native {host_arch} libFuzzer harness"
            )
            tools = _tool_records(
                toolchain_lock, ("oss-fuzz-gen", "quartetfuzz")
            )
            optional_tools = []
        elif support_index is not None:
            support = support_index.get(repository.casefold())
            if support is None and not bool(
                pipeline_config.get("allow_generic_integrations", True)
            ):
                return None, "no_pinned_oss_fuzz_project"
            if support is None:
                generic_build_signal = _generic_build_signal(assessment)
                if generic_build_signal is None:
                    return None, "no_supported_generic_build_signal"
                route = "oss_fuzz_generated"
                route_reason = "generate a private OSS-Fuzz project definition and harness"

    job_id = f"{_slug(repository)}-{commit[:12].lower()}"
    created_at = utc_now()
    return (
        {
            "schema_version": 1,
            "job_id": job_id,
            "created_at": created_at,
            "status": "queued",
            "source": {
                "repository": repository,
                "repository_url": candidate.get("repository_url"),
                "commit": commit.lower(),
                "default_branch": candidate.get("default_branch"),
                "language": language,
            },
            "authorization": {
                "policy_status": "verified",
                "policy_confidence": policy.get("confidence"),
                "policy_source": policy.get("source"),
                "program_url": policy.get("program_url"),
                "security_url": policy.get("security_url"),
                "observed_at": candidate.get("observed_at"),
                "recheck_before_build": True,
            },
            "route": {
                "name": route,
                "reason": route_reason,
                "required_tools": tools,
                "optional_tools": optional_tools,
            },
            "compatibility": {
                "checked": support_index is not None,
                "oss_fuzz_project": (support or {}).get("project"),
                "oss_fuzz_language": (support or {}).get("language"),
                "generic_build_signal": generic_build_signal,
                "host_arch": host_arch,
                "architecture_evidence": list(architecture.get("evidence") or []),
                "strategy": (
                    "native_generated_project"
                    if route == "native_generated"
                    else (
                        "pinned_existing_oss_fuzz_project"
                        if support
                        else "generated_private_oss_fuzz_project"
                    )
                ),
            },
            "ai": {
                "provider": "codex_cli",
                "model": pipeline_config["ai_model"],
                "reasoning_effort": pipeline_config["ai_reasoning_effort"],
                "max_harness_attempts": int(
                    pipeline_config["max_harness_attempts"]
                ),
                "uses": [
                    "entry_point_ranking",
                    "harness_generation",
                    "compile_error_repair",
                    "coverage_gap_review",
                    "crash_summary_for_human_review",
                ],
                "forbidden_decisions": [
                    "bug_bounty_policy_approval",
                    "crash_validity_without_reproduction",
                    "automatic_vulnerability_submission",
                ],
            },
            "budgets": {
                "setup_seconds": int(pipeline_config["setup_timeout_seconds"]),
                "smoke_seconds": int(pipeline_config["smoke_seconds"]),
                "fuzz_seconds": int(pipeline_config["fuzz_seconds"]),
                "triage_seconds": int(pipeline_config["triage_timeout_seconds"]),
                "coverage_stall_seconds": int(
                    pipeline_config["coverage_stall_seconds"]
                ),
                "afl_cmplog_seconds": int(
                    pipeline_config.get("afl_cmplog_seconds", 3600)
                ),
            },
            "execution": {
                "primary_engine": "libfuzzer",
                "stagnation_engine": "afl_cmplog",
                "primary_sanitizer": "address",
                "secondary_sanitizer": "undefined",
                "parallel_workers": int(pipeline_config["parallel_workers"]),
                "max_parallel_jobs": int(
                    pipeline_config.get("max_parallel_jobs", 0)
                ),
                "resource_allocation": (
                    "dynamic" if int(pipeline_config.get("parallel_workers", 0)) <= 0
                    or int(pipeline_config.get("container_memory_mb", 0)) <= 0
                    else "configured_caps"
                ),
                "network_during_fuzzing": False,
                "container_read_only_source": True,
                "host_arch": host_arch,
                "architecture_mode": str(
                    (architecture_config or {}).get("mode") or "legacy"
                ),
                "emulation_allowed": False,
            },
            "quality_gates": [
                "policy_revalidated_at_same_program_scope",
                "source_commit_matches_work_order",
                "build_succeeds_with_asan",
                "quartet_p1_logic_correctness",
                "quartet_p2_api_protocol_compliance",
                "quartet_p3_public_security_boundary",
                "quartet_p4_entry_point_adequacy",
                "smoke_run_is_deterministic",
                "fuzz_input_reaches_target_code",
                "crash_reproduces_at_least_3_of_3_runs",
            ],
            "candidate_assessment": assessment,
            "validation_handoff": {
                "required_inputs": [
                    "minimal_reproducer",
                    "reproducer_sha256",
                    "symbolized_sanitizer_stack",
                    "source_and_toolchain_commits",
                    "three_of_three_clean_reproductions",
                    "affected_public_api_or_cli_path",
                ],
                "expected_outputs": [
                    "reproduction_steps",
                    "non_weaponized_poc",
                    "trigger_conditions",
                    "impact_analysis",
                    "duplicate_search_notes",
                    "human_review_report_draft",
                ],
                "restrictions": [
                    "do_not_submit_automatically",
                    "do_not_generate_deployment_or_persistence",
                    "do_not_claim_impact_without_evidence",
                ],
            },
        },
        "",
    )


def list_jobs(runs_root: str | Path) -> list[dict[str, Any]]:
    root = Path(runs_root)
    if not root.is_dir():
        return []
    jobs: list[dict[str, Any]] = []
    for path in sorted(root.glob("*/state.json")):
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            job = json.loads((path.parent / "job.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        jobs.append(
            {
                "job_id": state.get("job_id", path.parent.name),
                "status": state.get("status", "unknown"),
                "stage": state.get("stage", "unknown"),
                "repository": (job.get("source") or {}).get("repository", "unknown"),
                "route": (job.get("route") or {}).get("name", "unknown"),
                "updated_at": state.get("updated_at", ""),
            }
        )
    return jobs


def job_status(runs_root: str | Path, job_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,160}", job_id):
        raise PipelineError(f"invalid job id: {job_id}")
    root = Path(runs_root).resolve()
    job_dir = (root / job_id).resolve()
    if job_dir.parent != root or not job_dir.is_dir() or job_dir.is_symlink():
        raise PipelineError(f"job directory was not found: {job_dir}")
    job = _read_object(job_dir / "job.json")
    state = _read_object(job_dir / "state.json")
    progress = _read_optional_object(job_dir / "artifacts" / "fuzz-progress.json")
    fuzz_run = _read_optional_object(job_dir / "artifacts" / "fuzz-run.json")
    probe_run = _read_optional_object(job_dir / "artifacts" / "probe-run.json")
    quartet = _read_optional_object(job_dir / "artifacts" / "quartet-review.json")
    target_selection = _read_optional_object(
        job_dir / "artifacts" / "target-selection.json"
    )
    afl_run = _read_optional_object(job_dir / "artifacts" / "afl-cmplog-run.json")
    triage = _read_optional_object(job_dir / "artifacts" / "triage-summary.json")
    validation = _read_optional_object(
        job_dir / "artifacts" / "validation-agent-report.json"
    )
    coverage_plan = _read_optional_object(job_dir / "artifacts" / "coverage-plan.json")
    adaptive = _read_optional_object(job_dir / "artifacts" / "adaptive-strategy.json")
    adaptive_current = next(
        (
            item
            for item in reversed(adaptive.get("history") or [])
            if isinstance(item, dict)
            and str(item.get("id") or "") == str(adaptive.get("current_id") or "")
        ),
        {},
    )
    budget = int((job.get("budgets") or {}).get("fuzz_seconds") or 0)
    completed = float(progress.get("completed_seconds") or 0)
    probe_findings = len(probe_run.get("crash_files") or [])
    probe_status = probe_run.get("status")
    if probe_run and not probe_status:
        probe_status = "sanitizer_finding" if probe_findings else "passed"
    selected_target = str(
        (coverage_plan.get("review") or {}).get("selected_fuzz_target") or ""
    )
    live = _live_fuzz_metrics(job_dir, state, selected_target)
    fuzz_target = (
        selected_target
        if live and selected_target
        else (
            fuzz_run.get("fuzz_target")
            or probe_run.get("fuzz_target")
            or selected_target
        )
    )
    worker_stats = fuzz_run.get("worker_stats") or []
    exec_per_second = sum(
        int(item.get("average_exec_per_sec") or 0)
        for item in worker_stats
        if isinstance(item, dict)
    )
    coverage_edges = max(
        (int(item.get("coverage_edges") or 0) for item in worker_stats if isinstance(item, dict)),
        default=0,
    )
    coverage_features = max(
        (int(item.get("coverage_features") or 0) for item in worker_stats if isinstance(item, dict)),
        default=0,
    )
    exec_per_second = live.get("exec_per_second", exec_per_second)
    coverage_edges = max(coverage_edges, live.get("coverage_edges", 0))
    coverage_features = max(coverage_features, live.get("coverage_features", 0))
    corpus_files = live.get("corpus_files", int(fuzz_run.get("corpus_files") or 0))
    crash_files = live.get("crash_files", len(fuzz_run.get("crash_files") or []))
    remaining = max(0.0, budget - completed)
    total_crashes = (
        probe_findings
        + crash_files
        + len(afl_run.get("crash_files") or [])
    )
    return {
        "job_id": job_id,
        "repository": (job.get("source") or {}).get("repository"),
        "commit": (job.get("source") or {}).get("commit"),
        "status": state.get("status"),
        "stage": state.get("stage"),
        "fuzz_target": fuzz_target,
        "fuzz_budget_seconds": budget,
        "fuzz_completed_seconds": completed,
        "fuzz_percent": round(min(100.0, completed * 100 / budget), 2) if budget else 0,
        "fuzz_remaining_seconds": round(remaining, 3),
        "exec_per_second": exec_per_second,
        "coverage_edges": coverage_edges,
        "coverage_features": coverage_features,
        "coverage_stalled": bool(progress.get("coverage_stalled")),
        "adaptive_strategy": adaptive_current.get("strategy"),
        "adaptive_strategy_status": adaptive_current.get("status"),
        "corpus_files": corpus_files,
        "crash_files": crash_files,
        "live_metrics_updated_at": live.get("updated_at"),
        "live_metrics_truncated": live.get("truncated", False),
        "preflight_target": probe_run.get("fuzz_target"),
        "preflight_status": probe_status,
        "preflight_findings": probe_findings,
        "quartet_verdict": (quartet.get("review") or {}).get("overall_verdict"),
        "attempted_fuzz_targets": list(
            state.get("attempted_fuzz_targets")
            or target_selection.get("attempted_fuzz_targets")
            or []
        ),
        "afl_cmplog_status": afl_run.get("status"),
        "afl_cmplog_new_corpus": int(afl_run.get("new_corpus_files") or 0),
        "afl_cmplog_crashes": len(afl_run.get("crash_files") or []),
        "finding_source": state.get("finding_source"),
        "triage_artifact": state.get("triage_artifact"),
        "validated_groups": int(triage.get("validated_group_count") or 0),
        "total_crashes": total_crashes,
        "validation_status": validation.get("status") or state.get("validation_status"),
        "false_positive_groups": sum(
            1 for group in triage.get("groups") or [] if not group.get("reproduced")
        ),
        "last_error": state.get("last_error"),
        "updated_at": state.get("updated_at"),
    }


def _live_fuzz_metrics(
    job_dir: Path, state: dict[str, Any], target: str
) -> dict[str, Any]:
    """Read only the active libFuzzer session's bounded host-side output."""
    if state.get("stage") != "fuzzing" or state.get("status") != "running":
        return {}
    if not state.get("active_fuzz_session_id"):
        return {}
    started = _pipeline_timestamp(
        str(state.get("active_fuzz_session_started_at") or "")
    )
    if started is None or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "pread"):
        return {}

    result: dict[str, Any] = {}
    workers: list[tuple[int, int, int, float]] = []
    try:
        runtime_fd = _open_live_directory(job_dir, "runtime-out", "fuzz")
    except OSError:
        runtime_fd = None
    if runtime_fd is not None:
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            for index in range(_LIVE_WORKER_LIMIT):
                try:
                    worker_fd = os.open(f"fuzz-{index}.log", flags, dir_fd=runtime_fd)
                except OSError:
                    continue
                try:
                    file_stat = os.fstat(worker_fd)
                    # A small allowance covers filesystems with coarse mtime precision.
                    if (
                        not stat.S_ISREG(file_stat.st_mode)
                        or file_stat.st_mtime < started.timestamp() - 2
                    ):
                        continue
                    length = min(file_stat.st_size, _LIVE_LOG_TAIL_BYTES)
                    tail = os.pread(worker_fd, length, file_stat.st_size - length)
                    if file_stat.st_size > length:
                        first_newline = tail.find(b"\n")
                        if first_newline < 0:
                            continue
                        tail = tail[first_newline + 1 :]
                    for line in reversed(tail.splitlines()):
                        match = _LIVE_LOG_LINE.match(line)
                        if match:
                            workers.append(
                                (
                                    int(match[1]),
                                    int(match[2]),
                                    int(match[3]),
                                    file_stat.st_mtime,
                                )
                            )
                            break
                except OSError:
                    continue
                finally:
                    os.close(worker_fd)
        finally:
            os.close(runtime_fd)
    if workers:
        result["coverage_edges"] = max(item[0] for item in workers)
        result["coverage_features"] = max(item[1] for item in workers)
        result["exec_per_second"] = sum(item[2] for item in workers)
        try:
            result["updated_at"] = datetime.fromtimestamp(
                max(item[3] for item in workers), timezone.utc
            ).isoformat()
        except (OSError, OverflowError, ValueError):
            pass

    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}", target):
        for field, category in (
            ("corpus_files", "corpus"),
            ("crash_files", "crashes"),
        ):
            counted = _count_live_files(job_dir, category, target)
            if counted is not None:
                result[field] = counted[0]
                if counted[1]:
                    result["truncated"] = True
    return result


def _open_live_directory(job_dir: Path, *parts: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(job_dir, flags)
    try:
        for part in parts:
            child_fd = os.open(part, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
    except OSError:
        os.close(directory_fd)
        raise
    return directory_fd


def _count_live_files(
    job_dir: Path, category: str, target: str
) -> tuple[int, bool] | None:
    try:
        directory_fd = _open_live_directory(job_dir, category, target)
    except OSError:
        return None
    try:
        count = 0
        with os.scandir(directory_fd) as entries:
            for index, entry in enumerate(entries):
                if index >= _LIVE_FILE_LIMIT:
                    return count, True
                if entry.is_file(follow_symlinks=False):
                    count += 1
        return count, False
    except OSError:
        return None
    finally:
        os.close(directory_fd)


def _read_optional_object(path: Path) -> dict[str, Any]:
    return _read_object(path) if path.is_file() else {}


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PipelineError(f"expected an object in {path}")
    return value


def load_toolchain_lock(path: str | Path) -> dict[str, Any]:
    lock_path = Path(path)
    if not lock_path.is_file():
        raise PipelineError(f"toolchain lock was not found: {lock_path}")
    try:
        value = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PipelineError(f"invalid toolchain lock: {exc.msg}") from exc
    if value.get("schema_version") != 1 or not isinstance(value.get("tools"), dict):
        raise PipelineError("unsupported toolchain lock schema")
    return value


def load_oss_fuzz_support_index(
    path: str | Path, toolchain_lock: dict[str, Any]
) -> dict[str, dict[str, str]]:
    index_path = Path(path)
    if not index_path.is_file():
        raise PipelineError(f"OSS-Fuzz support index was not found: {index_path}")
    try:
        value = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PipelineError(f"invalid OSS-Fuzz support index: {exc.msg}") from exc
    expected = str((toolchain_lock.get("tools") or {}).get("oss-fuzz", {}).get("commit") or "")
    if value.get("schema_version") != 1 or value.get("oss_fuzz_commit") != expected:
        raise PipelineError("OSS-Fuzz support index does not match the pinned tool commit")
    result: dict[str, dict[str, str]] = {}
    for item in value.get("projects") or []:
        repository = str(item.get("repository") or "").casefold()
        project = str(item.get("project") or "")
        if repository and project:
            result[repository] = {
                "project": project,
                "language": str(item.get("language") or ""),
            }
    return result


def _route(
    language: str,
    assessment: dict[str, Any],
    toolchain_lock: dict[str, Any],
) -> tuple[str | None, str, list[dict[str, str]], list[dict[str, str]]]:
    signals = [str(value).casefold() for value in assessment.get("signals") or []]
    entry_kind = str(assessment.get("suggested_entry_kind") or "").casefold()
    if language.casefold() in CPP_LANGUAGES:
        has_harness = entry_kind == "existing_harness" or any(
            value.startswith("existing_fuzz_assets:") for value in signals
        )
        route = "oss_fuzz_existing" if has_harness else "oss_fuzz_gen"
        reason = (
            "reuse and extend existing harnesses"
            if has_harness
            else "generate and validate a C/C++ harness"
        )
        required = _tool_records(
            toolchain_lock, ("oss-fuzz", "oss-fuzz-gen", "quartetfuzz")
        )
        optional = _tool_records(
            toolchain_lock, ("fuzz-introspector", "aflplusplus")
        )
        return route, reason, required, optional
    if language.casefold() == "python":
        return None, "vistafuzz_is_an_opencv_specific_auxiliary_artifact", [], []
    return None, "language_route_unavailable", [], []


def _tool_records(
    lock: dict[str, Any], names: tuple[str, ...]
) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    tools = lock["tools"]
    for name in names:
        item = tools.get(name)
        if not isinstance(item, dict):
            raise PipelineError(f"toolchain lock is missing {name}")
        records.append(
            {
                "name": name,
                "url": str(item["url"]),
                "commit": str(item["commit"]),
                "integration": str(item["integration"]),
            }
        )
    return records


def _generic_build_signal(assessment: dict[str, Any]) -> str | None:
    supported = {
        "cmakelists.txt": "cmake",
        "meson.build": "meson",
        "configure.ac": "autotools",
        "cargo.toml": "cargo",
    }
    for value in assessment.get("signals") or []:
        text = str(value).casefold()
        if not text.startswith("standard_build:"):
            continue
        for marker in text.removeprefix("standard_build:").split(","):
            if marker in supported:
                return supported[marker]
    return None


def _slug(repository: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", repository.casefold()).strip("-")


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
