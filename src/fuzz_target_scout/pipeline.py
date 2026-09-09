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
        work_order, reason = make_work_order(candidate, pipeline_config, toolchain_lock)
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
            },
            "execution": {
                "primary_engine": "libfuzzer",
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
