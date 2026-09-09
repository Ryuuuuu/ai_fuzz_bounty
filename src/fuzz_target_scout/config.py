from __future__ import annotations

import copy
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
        "validation_schema_path": "schemas/validation-agent.schema.json",
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
        "afl_cmplog_enabled": True,
        "afl_cmplog_seconds": 3600,
        "max_parallel_jobs": 0,
        "auto_parallel_job_cap": 4,
        "parallel_workers": 0,
        "max_workers_per_job": 6,
        "min_workers_per_job": 2,
        "resource_cpu_reserve": 1,
        "resource_memory_reserve_mb": 1024,
        "memory_per_fuzz_worker_mb": 768,
        "container_memory_overhead_mb": 384,
        "min_container_memory_mb": 1024,
        "inspect_docker_resources": True,
        "probe_seconds": 60,
        "container_memory_mb": 0,
        "fuzzer_rss_limit_mb": 1024,
        "input_timeout_seconds": 10,
        "job_disk_limit_mb": 20480,
        "corpus_limit_mb": 4096,
        "corpus_max_files": 100000,
        "log_max_files": 200,
        "runtime_retention_hours": 24,
        "max_stage_failures": 3,
        "dashboard_interval_seconds": 10,
        "allow_generic_integrations": True,
        "generic_integration_ai_timeout_seconds": 300,
        "vistafuzz_enabled": False,
        "vistafuzz_seconds": 3600,
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
    ("pipeline", "validation_schema_path"): "schemas/validation-agent.schema.json",
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
        ("pipeline", "validation_schema_path"),
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
