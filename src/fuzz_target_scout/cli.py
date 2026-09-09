from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .ai import AIError, CodexReviewer
from .config import load_config
from .engine import ScoutEngine
from .policy import PolicyVerifier
from .storage import Store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzz-target-scout",
        description="Discover Linux-friendly fuzzing candidates behind a strict bounty-policy gate.",
    )
    parser.add_argument("--config", default="config.toml", help="TOML configuration path")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run one discovery scan")
    scan.add_argument("--catalog-only", action="store_true")
    scan.add_argument("--limit", type=int)
    scan.add_argument("--query", action="append", dest="queries")
    scan.add_argument("--no-ai", action="store_true")

    daemon = subparsers.add_parser("daemon", help="Repeat scans at a fixed interval")
    daemon.add_argument("--catalog-only", action="store_true")
    daemon.add_argument("--limit", type=int)
    daemon.add_argument("--no-ai", action="store_true")
    daemon.add_argument("--interval-seconds", type=int)

    listing = subparsers.add_parser("list", help="List ranked candidates")
    listing.add_argument("--all", action="store_true")
    listing.add_argument("--limit", type=int, default=50)

    export = subparsers.add_parser("export", help="Export handoff-ready JSONL")
    export.add_argument("--output")
    export.add_argument("--minimum-score", type=int)
    export.add_argument("--include-conditional", action="store_true")

    subparsers.add_parser("doctor", help="Check local configuration")
    subparsers.add_parser("ai-check", help="Run one small Codex CLI structured-output check")
    subparsers.add_parser("catalog", help="Show curated policy-gate entries")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    config, config_path = load_config(args.config)
    try:
        if args.command == "doctor":
            _doctor(config, config_path)
        elif args.command == "ai-check":
            _ai_check(config)
        elif args.command == "catalog":
            _catalog(config)
        elif args.command == "scan":
            _scan(config, args)
        elif args.command == "daemon":
            _daemon(config, args)
        elif args.command == "list":
            _list(config, args)
        elif args.command == "export":
            _export(config, args)
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
        raise SystemExit(130)


def _scan(config: dict[str, Any], args: argparse.Namespace) -> None:
    engine = ScoutEngine(config, progress=lambda message: print(message, flush=True))
    try:
        summary = engine.scan(
            catalog_only=args.catalog_only,
            limit=args.limit,
            queries=getattr(args, "queries", None),
            use_ai=not args.no_ai,
        )
    finally:
        engine.close()
    print(
        "scan complete: "
        f"id={summary.scan_id} discovered={summary.discovered} "
        f"verified={summary.verified} conditional={summary.conditional} "
        f"review={summary.needs_review} rejected={summary.rejected} "
        f"ai_calls={summary.ai_calls} ai_cache_hits={summary.ai_cache_hits} "
        f"errors={summary.errors}"
    )


def _daemon(config: dict[str, Any], args: argparse.Namespace) -> None:
    interval = args.interval_seconds or int(config["daemon"]["interval_seconds"])
    if interval < 60:
        raise SystemExit("interval must be at least 60 seconds")
    while True:
        started = time.monotonic()
        _scan(config, args)
        remaining = max(0, interval - int(time.monotonic() - started))
        print(f"next scan in {remaining} seconds", flush=True)
        time.sleep(remaining)


def _list(config: dict[str, Any], args: argparse.Namespace) -> None:
    store = Store(config["storage"]["database_path"])
    try:
        rows = store.list_candidates(limit=args.limit, include_all=args.all)
    finally:
        store.close()
    if not rows:
        print("no candidates; run 'fuzz-target-scout scan --catalog-only' first")
        return
    headers = ("score", "diff", "policy", "ai", "language", "repository")
    data = [
        (
            str(row["final_score"]),
            str(row["reproduce_difficulty"]),
            row["policy_status"],
            "yes" if row["ai_used"] else "no",
            row["language"] or "-",
            row["full_name"],
        )
        for row in rows
    ]
    widths = [max(len(headers[i]), *(len(row[i]) for row in data)) for i in range(6)]
    print("  ".join(headers[i].ljust(widths[i]) for i in range(6)))
    print("  ".join("-" * width for width in widths))
    for row in data:
        print("  ".join(row[i].ljust(widths[i]) for i in range(6)))


def _export(config: dict[str, Any], args: argparse.Namespace) -> None:
    output = Path(args.output or config["storage"]["export_path"]).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    minimum = (
        args.minimum_score
        if args.minimum_score is not None
        else int(config["scoring"]["minimum_handoff_score"])
    )
    include_conditional = bool(
        args.include_conditional or config["policy"]["allow_conditional_handoff"]
    )
    store = Store(config["storage"]["database_path"])
    try:
        rows = list(store.export_rows(minimum, include_conditional))
    finally:
        store.close()
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    print(f"exported {len(rows)} candidates to {output}")


def _doctor(config: dict[str, Any], config_path: Path) -> None:
    catalog = Path(config["policy"]["catalog_path"])
    database = Path(config["storage"]["database_path"])
    checks = [
        ("config", "ok" if config_path.exists() else "using defaults", str(config_path)),
        ("catalog", "ok" if catalog.exists() else "missing", str(catalog)),
        ("database parent", "ok" if database.parent.exists() else "will create", str(database.parent)),
        ("GITHUB_TOKEN", "set" if os.environ.get("GITHUB_TOKEN") else "missing (low API rate limit)", ""),
        ("git", shutil.which("git") or "missing", ""),
        (
            "Codex CLI",
            shutil.which(str(config["ai"].get("executable") or "codex")) or "missing",
            _codex_login_status(str(config["ai"].get("executable") or "codex")),
        ),
        ("python", sys.version.split()[0], sys.executable),
        (
            "AI model",
            str(config["ai"]["model"]),
            f"reasoning={config['ai']['reasoning_effort']}",
        ),
    ]
    for name, status, detail in checks:
        print(f"{name:16} {status:28} {detail}")


def _codex_login_status(executable: str) -> str:
    if not shutil.which(executable):
        return ""
    try:
        result = subprocess.run(
            [executable, "login", "status"],
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "login status unavailable"
    message = (result.stdout or result.stderr).strip().splitlines()
    return message[-1][:120] if message else "login status unavailable"


def _catalog(config: dict[str, Any]) -> None:
    verifier = PolicyVerifier(
        config["policy"]["catalog_path"],
        int(config["policy"]["max_catalog_age_days"]),
    )
    if not verifier.entries:
        print("catalog is empty")
        return
    for entry in verifier.entries.values():
        print(
            f"{entry.get('status','needs_review'):12} "
            f"{entry.get('access','unknown'):8} "
            f"{entry['full_name']}  {entry.get('program_url','')}"
        )


def _ai_check(config: dict[str, Any]) -> None:
    reviewer = CodexReviewer(config["ai"])
    if not reviewer.available:
        raise SystemExit(f"Codex CLI executable '{reviewer.executable}' was not found")
    evidence = {
        "repository": "example/parser",
        "description": "Small Linux parser library with an existing local fuzz harness",
        "primary_language": "Rust",
        "stars": 100,
        "size_kb": 12000,
        "path_count_seen": 120,
        "interesting_paths": [
            "Cargo.toml",
            "fuzz/Cargo.toml",
            "fuzz/fuzz_targets/parse.rs",
            "tests/corpus/minimal.bin",
        ],
        "static_score": 85,
        "static_difficulty": 1,
        "signals": ["existing_fuzz_assets:3", "linux_evidence", "test_suite"],
        "blockers": [],
        "policy_gate": "verified",
    }
    try:
        assessment, usage = reviewer.assess(evidence)
    except AIError as exc:
        raise SystemExit(str(exc)) from exc
    print(
        f"AI check ok: model={reviewer.model} reasoning={reviewer.reasoning_effort} "
        f"score={assessment.fuzz_score} difficulty={assessment.reproduce_difficulty} "
        f"input_tokens={usage['input_tokens']} cached_tokens={usage['cached_tokens']} "
        f"output_tokens={usage['output_tokens']}"
    )


if __name__ == "__main__":
    main()
