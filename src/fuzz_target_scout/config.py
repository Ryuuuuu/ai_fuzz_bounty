from __future__ import annotations

import copy
import os
import tomllib
from importlib.resources import files
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
        "oss_fuzz_index_path": "oss-fuzz-support.json",
        "languages": ["C", "C++"],
        "ai_model": "gpt-daybreak-blue-latest",
        "ai_reasoning_effort": "high",
        "ai_executable": "codex",
        "coverage_schema_path": "schemas/coverage-review.schema.json",
        "quartet_schema_path": "schemas/quartet-review.schema.json",
        "triage_schema_path": "schemas/triage-report.schema.json",
        "coverage_ai_timeout_seconds": 180,
        "quartet_ai_timeout_seconds": 180,
        "generation_ai_timeout_seconds": 240,
        "generation_max_tokens": 4096,
        "max_generation_cycles": 2,
        "introspector_endpoint": "https://introspector.oss-fuzz.com/api",
        "introspector_timeout_seconds": 30,
        "coverage_candidate_limit": 10,
        "max_harness_attempts": 3,
        "max_fuzz_target_attempts": 3,
        "setup_timeout_seconds": 5400,
        "smoke_seconds": 300,
        "fuzz_seconds": 86400,
        "fuzz_checkpoint_seconds": 3600,
        "triage_timeout_seconds": 3600,
        "triage_reproduction_attempts": 3,
        "triage_max_crashes": 20,
        "triage_ubsan_enabled": True,
        "coverage_stall_seconds": 14400,
        "parallel_workers": 0,
        "probe_seconds": 60,
        "container_memory_mb": 0,
        "fuzzer_rss_limit_mb": 1024,
        "input_timeout_seconds": 10,
    },
    "daemon": {"interval_seconds": 21600},
}


_PACKAGED_INPUTS = {
    ("policy", "catalog_path"): "catalog.json",
    ("ai", "schema_path"): "schemas/candidate-assessment.schema.json",
    ("pipeline", "toolchain_lock_path"): "toolchain.lock.json",
    ("pipeline", "oss_fuzz_index_path"): "oss-fuzz-support.json",
    ("pipeline", "coverage_schema_path"): "schemas/coverage-review.schema.json",
    ("pipeline", "quartet_schema_path"): "schemas/quartet-review.schema.json",
    ("pipeline", "triage_schema_path"): "schemas/triage-report.schema.json",
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
    if int(config["pipeline"]["parallel_workers"]) <= 0:
        config["pipeline"]["parallel_workers"] = min(
            6, max(1, (os.cpu_count() or 2) - 1)
        )
    if int(config["pipeline"]["container_memory_mb"]) <= 0:
        available_mb = _available_memory_mb()
        config["pipeline"]["container_memory_mb"] = max(
            512, min(6144, int(available_mb * 0.65))
        )
        config["pipeline"]["fuzzer_rss_limit_mb"] = min(
            int(config["pipeline"]["fuzzer_rss_limit_mb"]),
            max(256, int(config["pipeline"]["container_memory_mb"]) - 384),
        )
    base = config_path.parent
    path_settings = (
        ("policy", "catalog_path"),
        ("ai", "schema_path"),
        ("storage", "database_path"),
        ("storage", "export_path"),
        ("pipeline", "input_path"),
        ("pipeline", "runs_path"),
        ("pipeline", "tools_path"),
        ("pipeline", "toolchain_lock_path"),
        ("pipeline", "oss_fuzz_index_path"),
        ("pipeline", "coverage_schema_path"),
        ("pipeline", "quartet_schema_path"),
        ("pipeline", "triage_schema_path"),
    )
    for section, key in path_settings:
        value = Path(config[section][key]).expanduser()
        if not value.is_absolute():
            value = base / value
        packaged_name = _PACKAGED_INPUTS.get((section, key))
        explicitly_configured = key in (loaded.get(section) or {})
        if packaged_name and not explicitly_configured and not value.exists():
            value = Path(
                str(files("fuzz_target_scout").joinpath("resources", packaged_name))
            )
        config[section][key] = str(value.resolve())
    return config, config_path


def _available_memory_mb() -> int:
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("MemAvailable:"):
                return max(512, int(line.split()[1]) // 1024)
    try:
        return max(
            512,
            int(os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 1024**2),
        )
    except (AttributeError, OSError, ValueError):
        return 4096
