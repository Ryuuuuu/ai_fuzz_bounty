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
from .pipeline_runner import PipelineRunner, STAGE_ORDER


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
    prepare = commands.add_parser(
        "prepare", help="Recheck policy, checkout source and sync pinned tools"
    )
    prepare.add_argument("--job-id", required=True)
    prepare.add_argument("--until", choices=STAGE_ORDER, default="integration")
    integrate = commands.add_parser(
        "integrate", help="Reuse a matching pinned OSS-Fuzz project definition"
    )
    integrate.add_argument("--job-id", required=True)
    build = commands.add_parser("build", help="Build ASan/libFuzzer targets")
    build.add_argument("--job-id", required=True)
    smoke = commands.add_parser("smoke", help="Run a short OSS-Fuzz build check")
    smoke.add_argument("--job-id", required=True)
    probe = commands.add_parser("probe", help="Run a short isolated fuzzing probe")
    probe.add_argument("--job-id", required=True)
    run = commands.add_parser("run", help="Run the full work-order fuzzing budget")
    run.add_argument("--job-id", required=True)
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
        elif args.command == "prepare":
            _prepare(config, args)
        elif args.command == "integrate":
            _integrate(config, args)
        elif args.command == "build":
            _build(config, args)
        elif args.command == "smoke":
            _smoke(config, args)
        elif args.command == "probe":
            _probe(config, args)
        elif args.command == "run":
            _run(config, args)
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


def _prepare(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    state = runner.prepare(args.job_id, args.until)
    print(
        f"prepare complete: job_id={args.job_id} status={state['status']} "
        f"stage={state['stage']}"
    )


def _integrate(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    state = runner.integrate(args.job_id)
    print(f"integration complete: job_id={args.job_id} stage={state['stage']}")


def _build(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    state = runner.build(args.job_id)
    print(f"build complete: job_id={args.job_id} stage={state['stage']}")


def _smoke(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    state = runner.smoke(args.job_id)
    print(f"smoke complete: job_id={args.job_id} stage={state['stage']}")


def _probe(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    result = runner.probe(args.job_id)
    print(
        f"probe complete: target={result['fuzz_target']} "
        f"corpus={result['corpus_files']} crashes={len(result['crash_files'])}"
    )


def _run(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    result = runner.fuzz(args.job_id)
    print(
        f"fuzz complete: target={result['fuzz_target']} "
        f"seconds={result['elapsed_seconds']} crashes={len(result['crash_files'])}"
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
        ("tools root", str(Path(pipeline["tools_path"]))),
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
