from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .pipeline import PipelineError, utc_now


RUNTIME_STRATEGIES = (
    "enable_value_profile",
    "inject_dictionary_seeds",
    "deepen_mutation_stack",
)
ALL_STRATEGIES = (*RUNTIME_STRATEGIES, "generate_followup_harness")
STRATEGY_DESCRIPTIONS = {
    "enable_value_profile": (
        "Enable libFuzzer value profiling so comparisons contribute feedback."
    ),
    "inject_dictionary_seeds": (
        "Turn bounded dictionary tokens into content-addressed seed inputs."
    ),
    "deepen_mutation_stack": (
        "Increase the bounded libFuzzer mutation stack depth from its default."
    ),
    "generate_followup_harness": (
        "Run the existing Quartet and OSS-Fuzz-Gen gated follow-up harness path."
    ),
}


def strategy_path(job_dir: Path) -> Path:
    return job_dir / "artifacts" / "adaptive-strategy.json"


def load_strategy_record(job_dir: Path) -> dict[str, Any]:
    path = strategy_path(job_dir)
    if not path.is_file():
        return {"schema_version": 1, "history": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"could not read adaptive strategy state: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("history"), list):
        raise PipelineError("adaptive strategy state is invalid")
    return value


def current_strategy(record: dict[str, Any]) -> dict[str, Any] | None:
    current_id = str(record.get("current_id") or "")
    for item in reversed(record.get("history") or []):
        if isinstance(item, dict) and str(item.get("id") or "") == current_id:
            return item
    return None


def attempted_strategies(record: dict[str, Any]) -> set[str]:
    return {
        str(item.get("strategy") or "")
        for item in record.get("history") or []
        if isinstance(item, dict)
    }


def queue_strategy(
    job_dir: Path,
    strategy: str,
    rationale: str,
    evaluation_seconds: int,
) -> dict[str, Any]:
    if strategy not in ALL_STRATEGIES:
        raise PipelineError(f"adaptive strategy is not allowlisted: {strategy}")
    record = load_strategy_record(job_dir)
    active = current_strategy(record)
    if active and active.get("status") in {"pending", "active"}:
        return active
    if strategy in attempted_strategies(record):
        raise PipelineError(f"adaptive strategy was already attempted: {strategy}")
    identifier = hashlib.sha256(
        f"{job_dir.name}:{strategy}:{len(record['history'])}".encode()
    ).hexdigest()[:16]
    entry = {
        "id": identifier,
        "strategy": strategy,
        "status": "pending",
        "queued_at": utc_now(),
        "rationale": str(rationale)[:1200],
        "evaluation_seconds": max(300, int(evaluation_seconds)),
    }
    record["history"].append(entry)
    record["current_id"] = identifier
    record.pop("exhausted_at", None)
    _write_json(strategy_path(job_dir), record)
    return entry


def activate_runtime_strategy(
    job_dir: Path, progress: dict[str, Any]
) -> dict[str, Any] | None:
    record = load_strategy_record(job_dir)
    entry = current_strategy(record)
    if not entry or entry.get("strategy") not in RUNTIME_STRATEGIES:
        return entry
    if entry.get("status") == "pending":
        entry["status"] = "active"
        entry["activated_at"] = utc_now()
        entry["baseline"] = {
            "completed_seconds": float(progress.get("completed_seconds") or 0),
            "coverage_edges": int(progress.get("last_coverage_edges") or 0),
            "coverage_features": int(progress.get("last_coverage_features") or 0),
            "corpus_files": int(progress.get("last_corpus_files") or 0),
        }
        _write_json(strategy_path(job_dir), record)
    return entry


def runtime_arguments(job_dir: Path) -> list[str]:
    entry = current_strategy(load_strategy_record(job_dir))
    if not entry or entry.get("status") != "active":
        return []
    strategy = entry.get("strategy")
    if strategy == "enable_value_profile":
        return ["-use_value_profile=1"]
    if strategy == "deepen_mutation_stack":
        return ["-mutate_depth=10"]
    return []


def inject_dictionary_seeds(
    job_dir: Path, dictionary_path: Path, corpus_dir: Path
) -> int:
    record = load_strategy_record(job_dir)
    entry = current_strategy(record)
    if (
        not entry
        or entry.get("status") != "active"
        or entry.get("strategy") != "inject_dictionary_seeds"
        or entry.get("seed_injection_completed")
    ):
        return 0
    tokens: list[bytes] = []
    if dictionary_path.is_file() and not dictionary_path.is_symlink():
        for line in dictionary_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()[:512]:
            value = line.strip()
            if "=" in value and not value.startswith('"'):
                value = value.split("=", 1)[1].strip()
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError:
                continue
            if not isinstance(decoded, str):
                continue
            content = decoded.encode("utf-8", errors="ignore")
            if 0 < len(content) <= 4096:
                tokens.append(content)
            if len(tokens) >= 128:
                break
    seeds = list(tokens)
    seeds.extend(tokens[index] + tokens[index + 1] for index in range(len(tokens) - 1))
    added = 0
    for content in seeds[:256]:
        destination = corpus_dir / hashlib.sha256(content).hexdigest()
        if destination.is_symlink() or (
            destination.exists() and not destination.is_file()
        ):
            continue
        if not destination.exists():
            destination.write_bytes(content)
            added += 1
    entry["seed_injection_completed"] = True
    entry["seed_files_added"] = added
    _write_json(strategy_path(job_dir), record)
    return added


def evaluate_runtime_strategy(
    job_dir: Path,
    progress: dict[str, Any],
    *,
    coverage_advanced: bool,
) -> dict[str, Any] | None:
    record = load_strategy_record(job_dir)
    entry = current_strategy(record)
    if not entry or entry.get("status") != "active":
        return entry
    baseline = entry.get("baseline") or {}
    elapsed = max(
        0.0,
        float(progress.get("completed_seconds") or 0)
        - float(baseline.get("completed_seconds") or 0),
    )
    entry["evaluated_seconds"] = round(elapsed, 3)
    entry["latest"] = {
        "coverage_edges": int(progress.get("last_coverage_edges") or 0),
        "coverage_features": int(progress.get("last_coverage_features") or 0),
        "corpus_files": int(progress.get("last_corpus_files") or 0),
    }
    if coverage_advanced:
        entry["status"] = "succeeded"
        entry["completed_at"] = utc_now()
        entry["outcome"] = "new coverage was observed"
    elif elapsed >= int(entry.get("evaluation_seconds") or 3600):
        entry["status"] = "ineffective"
        entry["completed_at"] = utc_now()
        entry["outcome"] = "no new coverage in the evaluation window"
    _write_json(strategy_path(job_dir), record)
    return entry


def complete_harness_strategy(
    job_dir: Path, *, status: str, outcome: str
) -> dict[str, Any] | None:
    record = load_strategy_record(job_dir)
    entry = current_strategy(record)
    if not entry or entry.get("strategy") != "generate_followup_harness":
        return entry
    entry["status"] = status
    entry["completed_at"] = utc_now()
    entry["outcome"] = str(outcome)[:1200]
    _write_json(strategy_path(job_dir), record)
    return entry


def mark_exhausted(job_dir: Path) -> bool:
    record = load_strategy_record(job_dir)
    if record.get("exhausted_at"):
        return False
    record["exhausted_at"] = utc_now()
    _write_json(strategy_path(job_dir), record)
    return True


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
