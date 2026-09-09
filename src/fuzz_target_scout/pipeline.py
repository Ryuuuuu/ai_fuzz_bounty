from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{7,64}$")
CPP_LANGUAGES = {"c", "c++", "cpp"}


class PipelineError(RuntimeError):
    pass


class UnsupportedIntegrationError(PipelineError):
    """The target is valid but has no safely reusable build integration."""


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

    for candidate in candidates:
        if limit is not None and created + existing >= limit:
            break
        work_order, reason = make_work_order(
            candidate, pipeline_config, toolchain_lock, support_index
        )
        if work_order is None:
            reasons[reason] += 1
            continue
        job_id = work_order["job_id"]
        job_ids.append(job_id)
        job_dir = root / job_id
        if (job_dir / "job.json").is_file():
            existing += 1
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
                "schema_version": 1,
                "job_id": job_id,
                "status": "queued",
                "stage": "policy_recheck",
                "created_at": work_order["created_at"],
                "updated_at": work_order["created_at"],
                "attempts": {},
                "last_error": None,
            },
        )
        created += 1
    return PlanSummary(
        created=created,
        existing=existing,
        skipped=sum(reasons.values()),
        skip_reasons=dict(sorted(reasons.items())),
        job_ids=job_ids,
    )


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
    route, route_reason, tools, optional_tools = _route(
        language, assessment, toolchain_lock
    )
    if route is None:
        return None, route_reason
    support = None
    if language.casefold() in CPP_LANGUAGES and support_index is not None:
        support = support_index.get(repository.casefold())
        if support is None:
            return None, "no_pinned_oss_fuzz_project"

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
                "network_during_fuzzing": False,
                "container_read_only_source": True,
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
    budget = int((job.get("budgets") or {}).get("fuzz_seconds") or 0)
    completed = float(progress.get("completed_seconds") or 0)
    probe_findings = len(probe_run.get("crash_files") or [])
    probe_status = probe_run.get("status")
    if probe_run and not probe_status:
        probe_status = "sanitizer_finding" if probe_findings else "passed"
    return {
        "job_id": job_id,
        "repository": (job.get("source") or {}).get("repository"),
        "commit": (job.get("source") or {}).get("commit"),
        "status": state.get("status"),
        "stage": state.get("stage"),
        "fuzz_budget_seconds": budget,
        "fuzz_completed_seconds": completed,
        "fuzz_percent": round(min(100.0, completed * 100 / budget), 2) if budget else 0,
        "coverage_stalled": bool(progress.get("coverage_stalled")),
        "corpus_files": int(fuzz_run.get("corpus_files") or 0),
        "crash_files": len(fuzz_run.get("crash_files") or []),
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
        "last_error": state.get("last_error"),
        "updated_at": state.get("updated_at"),
    }


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
        required = _tool_records(toolchain_lock, ("vistafuzz",))
        optional = _tool_records(toolchain_lock, ("quartetfuzz",))
        return "vistafuzz", "extract documented API constraints once", required, optional
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


def _slug(repository: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", repository.casefold()).strip("-")


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
