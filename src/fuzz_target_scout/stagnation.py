from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .pipeline import PipelineError, utc_now


STRING_LITERAL = re.compile(r'(?<![A-Za-z0-9_])(?:u8|u|U|L)?"((?:\\.|[^"\\]){3,96})"')


def generate_dictionary(job_dir: Path, fuzz_target: str) -> dict[str, Any]:
    build = _read_json(job_dir / "artifacts" / "build-manifest.json")
    output = Path(str(build.get("output_directory") or "")).resolve()
    expected_root = (job_dir / "build-output").resolve()
    if not output.is_dir() or expected_root not in output.parents:
        raise PipelineError("stagnation dictionary build output escaped the job")
    tokens: set[str] = set()
    roots = [job_dir / "integration", job_dir / "source"]
    files = []
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            continue
        files.extend(
            path for path in sorted(root.rglob("*"))
            if path.is_file() and not path.is_symlink()
            and path.suffix.casefold() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
        )
    for path in files[:300]:
        try:
            if path.stat().st_size > 500_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in STRING_LITERAL.finditer(text):
            value = match.group(1)
            if _useful(value):
                tokens.add(value)
            if len(tokens) >= 512:
                break
        if len(tokens) >= 512:
            break
    rendered = "".join(f'"{_escape(value)}"\n' for value in sorted(tokens, key=lambda v: (len(v), v)))
    destination = output / f"{fuzz_target}.dict"
    if tokens:
        destination.write_text(rendered, encoding="utf-8")
        for runtime in (job_dir / "runtime-out").glob("*"):
            if runtime.is_dir() and not runtime.is_symlink():
                (runtime / destination.name).write_text(rendered, encoding="utf-8")
    else:
        destination.unlink(missing_ok=True)
    record = {
        "schema_version": 1,
        "created_at": utc_now(),
        "fuzz_target": fuzz_target,
        "token_count": len(tokens),
        "path": str(destination) if tokens else None,
        "sha256": hashlib.sha256(rendered.encode()).hexdigest(),
        "source": "bounded_static_string_extraction_after_afl_cmplog",
    }
    _write_json(job_dir / "artifacts" / "stagnation-dictionary.json", record)
    return record


def _useful(value: str) -> bool:
    if not any(character.isalnum() for character in value):
        return False
    return not any(ord(character) < 0x20 and character not in "\\n\\r\\t" for character in value)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PipelineError(f"expected an object in {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
