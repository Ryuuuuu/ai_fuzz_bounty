from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .pipeline import PipelineError, utc_now


CURRENT_STATE_SCHEMA = 2


def migrate_runs(runs_root: str | Path, *, dry_run: bool = False) -> dict[str, Any]:
    root = Path(runs_root)
    root.mkdir(parents=True, exist_ok=True)
    migrated: list[str] = []
    current: list[str] = []
    failed: dict[str, str] = {}
    for path in sorted(root.glob("*/state.json")):
        job_id = path.parent.name
        try:
            state = _read(path)
            version = int(state.get("schema_version") or 1)
            if version > CURRENT_STATE_SCHEMA:
                raise PipelineError(f"state schema {version} is newer than this package")
            if version == CURRENT_STATE_SCHEMA:
                current.append(job_id)
                continue
            migrated_state = _migrate_state(state, version)
            if not dry_run:
                backup = path.parent / f"state.v{version}.json"
                if not backup.exists():
                    shutil.copy2(path, backup)
                _write(path, migrated_state)
            migrated.append(job_id)
        except (OSError, ValueError, PipelineError) as exc:
            failed[job_id] = str(exc)[:1000]
    return {
        "schema_version": 1,
        "created_at": utc_now(),
        "dry_run": dry_run,
        "target_state_schema": CURRENT_STATE_SCHEMA,
        "migrated": migrated,
        "already_current": current,
        "failed": failed,
    }


def _migrate_state(state: dict[str, Any], version: int) -> dict[str, Any]:
    value = dict(state)
    if version <= 1:
        value.setdefault("attempts", {})
        value.setdefault("validation_status", None)
        value.setdefault("last_error", None)
        value["schema_version"] = 2
        value["migrated_at"] = utc_now()
    return value


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PipelineError(f"expected an object in {path}")
    return value


def _write(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
