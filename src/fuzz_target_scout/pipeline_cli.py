from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

from .config import load_config
from .pipeline import (
    PipelineError,
    list_jobs,
    load_jsonl,
    load_toolchain_lock,
    prepare_jobs,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzz-pipeline",
        description="Prepare policy-gated fuzzing work orders from scout exports.",
    )
    parser.add_argument("--config", default="config.toml")
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="Create immutable fuzzing work orders")
    plan.add_argument("--input")
    plan.add_argument("--runs-root")
    plan.add_argument("--limit", type=int)
    listing = commands.add_parser("list", help="List prepared work orders")
    listing.add_argument("--runs-root")
    commands.add_parser("doctor", help="Check fuzzing pipeline prerequisites")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    config, _ = load_config(args.config)
    try:
        if args.command == "plan":
            _plan(config, args)
        elif args.command == "list":
            _list(config, args)
        elif args.command == "doctor":
            _doctor(config)
    except PipelineError as exc:
        raise SystemExit(str(exc)) from exc


def _plan(config: dict, args: argparse.Namespace) -> None:
    pipeline = config["pipeline"]
    input_path = args.input or pipeline["input_path"]
    runs_root = args.runs_root or pipeline["runs_path"]
    lock = load_toolchain_lock(pipeline["toolchain_lock_path"])
    summary = prepare_jobs(
        load_jsonl(input_path), runs_root, pipeline, lock, limit=args.limit
    )
    print(
        f"plan complete: created={summary.created} existing={summary.existing} "
        f"skipped={summary.skipped} runs_root={Path(runs_root)}"
    )
    for reason, count in summary.skip_reasons.items():
        print(f"skip {reason}: {count}")
    for job_id in summary.job_ids:
        print(job_id)


def _list(config: dict, args: argparse.Namespace) -> None:
    runs_root = args.runs_root or config["pipeline"]["runs_path"]
    jobs = list_jobs(runs_root)
    if not jobs:
        print("no jobs; run 'fuzz-pipeline plan' after exporting candidates")
        return
    for job in jobs:
        print(
            f"{job['status']:12} {job['stage']:24} {job['route']:20} "
            f"{job['repository']}  {job['job_id']}"
        )


def _doctor(config: dict) -> None:
    pipeline = config["pipeline"]
    checks = [
        ("git", shutil.which("git") or "missing"),
        ("docker cli", shutil.which("docker") or "missing"),
        ("codex cli", shutil.which("codex") or "missing"),
        (
            "toolchain lock",
            "ok" if Path(pipeline["toolchain_lock_path"]).is_file() else "missing",
        ),
        ("runs root", str(Path(pipeline["runs_path"]))),
        ("AI model", f"{pipeline['ai_model']} ({pipeline['ai_reasoning_effort']})"),
    ]
    daemon = _docker_server_status()
    checks.insert(2, ("docker daemon", daemon))
    for name, value in checks:
        print(f"{name:18} {value}")


def _docker_server_status() -> str:
    if not shutil.which("docker"):
        return "unavailable"
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    if result.returncode == 0:
        return f"ok ({result.stdout.strip()})"
    detail = (result.stderr or result.stdout).strip().splitlines()
    return f"blocked ({detail[-1][:100] if detail else 'unknown error'})"


if __name__ == "__main__":
    main()
