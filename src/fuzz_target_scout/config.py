from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any


DEFAULTS: dict[str, Any] = {
    "github": {
        "api_url": "https://api.github.com",
        "per_query": 20,
        "max_tree_paths": 5000,
        "timeout_seconds": 20,
        "queries": [
            "archived:false fork:false pushed:>={pushed_after} stars:20..10000 language:C",
            "archived:false fork:false pushed:>={pushed_after} stars:20..10000 language:C++",
            "archived:false fork:false pushed:>={pushed_after} stars:20..10000 language:Rust",
            "archived:false fork:false pushed:>={pushed_after} stars:20..10000 language:Go",
        ],
    },
    "policy": {
        "catalog_path": "catalog.json",
        "max_catalog_age_days": 45,
        "allow_conditional_handoff": False,
    },
    "scoring": {"minimum_static_score": 35, "minimum_handoff_score": 55},
    "ai": {
        "enabled": True,
        "provider": "codex_cli",
        "executable": "codex",
        "model": "gpt-daybreak-blue-latest",
        "reasoning_effort": "high",
        "max_candidates_per_scan": 5,
        "minimum_static_score": 50,
        "prompt_version": "candidate-assessment-v1",
        "timeout_seconds": 90,
        "schema_path": "schemas/candidate-assessment.schema.json",
    },
    "storage": {
        "database_path": "data/scout.sqlite3",
        "export_path": "data/verified-candidates.jsonl",
    },
    "pipeline": {
        "input_path": "data/verified-candidates.jsonl",
        "runs_path": "data/runs",
        "tools_path": ".tools",
        "toolchain_lock_path": "toolchain.lock.json",
        "languages": ["C", "C++"],
        "ai_model": "gpt-daybreak-blue-latest",
        "ai_reasoning_effort": "high",
        "ai_executable": "codex",
        "coverage_schema_path": "schemas/coverage-review.schema.json",
        "coverage_ai_timeout_seconds": 180,
        "introspector_endpoint": "https://introspector.oss-fuzz.com/api",
        "introspector_timeout_seconds": 30,
        "coverage_candidate_limit": 10,
        "max_harness_attempts": 3,
        "setup_timeout_seconds": 5400,
        "smoke_seconds": 300,
        "fuzz_seconds": 86400,
        "triage_timeout_seconds": 3600,
        "coverage_stall_seconds": 14400,
        "parallel_workers": 6,
        "probe_seconds": 60,
        "container_memory_mb": 6144,
        "fuzzer_rss_limit_mb": 1024,
        "input_timeout_seconds": 10,
    },
    "daemon": {"interval_seconds": 21600},
}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str | Path | None = None) -> tuple[dict[str, Any], Path]:
    config_path = Path(path or "config.toml").expanduser().resolve()
    loaded: dict[str, Any] = {}
    if config_path.exists():
        with config_path.open("rb") as handle:
            loaded = tomllib.load(handle)
    config = _merge(DEFAULTS, loaded)
    base = config_path.parent
    for section, key in (
        ("policy", "catalog_path"),
        ("ai", "schema_path"),
        ("storage", "database_path"),
        ("storage", "export_path"),
        ("pipeline", "input_path"),
        ("pipeline", "runs_path"),
        ("pipeline", "tools_path"),
        ("pipeline", "toolchain_lock_path"),
        ("pipeline", "coverage_schema_path"),
    ):
        value = Path(config[section][key]).expanduser()
        if not value.is_absolute():
            value = base / value
        config[section][key] = str(value.resolve())
    return config, config_path
