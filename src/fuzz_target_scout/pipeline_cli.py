from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import shutil
import subprocess
import time
from pathlib import Path

from .architecture import resolve_host_architecture
from .config import load_config
from .central_agent import CentralAgent
from .pipeline import (
    PipelineError,
    list_jobs,
    job_status,
    load_jsonl,
    load_oss_fuzz_support_index,
    load_toolchain_lock,
    prepare_jobs,
)
from .pipeline_runner import PipelineRunner, STAGE_ORDER
from .pipeline_worker import PipelineWorker
from .operations import Housekeeper, pipeline_overview
from .resources import plan_resources
from .triage import TriageRunner
from .validation_agent import ValidationAgentRunner
from .migrations import migrate_runs
from .vistafuzz_adapter import VistaFuzzAdapter


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
    status = commands.add_parser("status", help="Show one work order's progress")
    status.add_argument("--job-id", required=True)
    status.add_argument("--json", action="store_true")
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
    quartet = commands.add_parser(
        "quartet", help="Audit the selected harness against QuartetFuzz P1-P4"
    )
    quartet.add_argument("--job-id", required=True)
    analyze = commands.add_parser(
        "analyze", help="Rank pinned-source coverage gaps with one local Codex review"
    )
    analyze.add_argument("--job-id", required=True)
    generate = commands.add_parser(
        "generate", help="Generate and build a focused harness through OSS-Fuzz-Gen"
    )
    generate.add_argument("--job-id", required=True)
    run = commands.add_parser("run", help="Run the full work-order fuzzing budget")
    run.add_argument("--job-id", required=True)
    afl = commands.add_parser(
        "afl-cmplog", help="Run the optional AFL++ CmpLog lane after a coverage stall"
    )
    afl.add_argument("--job-id", required=True)
    triage = commands.add_parser(
        "triage", help="Minimize, reproduce and deduplicate sanitizer crashes"
    )
    triage.add_argument("--job-id", required=True)
    triage.add_argument("--no-ai", action="store_true")
    validate = commands.add_parser(
        "validate", help="Create local PoCs and a human-review report for reproduced crashes"
    )
    validate.add_argument("--job-id", required=True)
    worker = commands.add_parser(
        "worker", help="Advance queued jobs through their 24-hour fuzz budget"
    )
    worker.add_argument("--max-jobs", type=int, default=0)
    worker.add_argument("--setup-only", action="store_true")
    agent = commands.add_parser(
        "agent", help="Run the AI-supervised fuzz campaign coordinator"
    )
    agent.add_argument("--max-batches", type=int, default=0)
    agent.add_argument("--once", action="store_true")
    agent.add_argument("--exit-when-idle", action="store_true")
    agent.add_argument("--no-discovery", action="store_true")
    agent.add_argument("--test-telegram", action="store_true")
    dashboard = commands.add_parser(
        "dashboard", help="Show jobs, throughput, findings and remaining budgets"
    )
    dashboard.add_argument("--json", action="store_true")
    dashboard.add_argument("--watch", action="store_true")
    dashboard.add_argument("--interval", type=int)
    housekeep = commands.add_parser(
        "housekeep", help="Enforce disk limits and remove orphan containers"
    )
    housekeep.add_argument("--job-id")
    housekeep.add_argument("--json", action="store_true")
    migrate = commands.add_parser("migrate", help="Upgrade existing run state files safely")
    migrate.add_argument("--dry-run", action="store_true")
    vista = commands.add_parser(
        "vistafuzz", help="Inspect or smoke-test the pinned OpenCV VistaFuzz artifact"
    )
    vista.add_argument("--smoke-seconds", type=int)
    commands.add_parser("doctor", help="Check fuzzing pipeline prerequisites")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    config, _ = load_config(args.config)
    if args.command not in {
        "doctor", "list", "status", "plan", "dashboard"
    } and platform.system() != "Linux":
        raise SystemExit("fuzz execution requires Linux (Ubuntu or WSL2)")
    try:
        if args.command == "plan":
            _plan(config, args)
        elif args.command == "list":
            _list(config, args)
        elif args.command == "status":
            _status(config, args)
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
        elif args.command == "quartet":
            _quartet(config, args)
        elif args.command == "analyze":
            _analyze(config, args)
        elif args.command == "generate":
            _generate(config, args)
        elif args.command == "run":
            _run(config, args)
        elif args.command == "afl-cmplog":
            _afl_cmplog(config, args)
        elif args.command == "triage":
            _triage(config, args)
        elif args.command == "validate":
            _validate(config, args)
        elif args.command == "worker":
            _worker(config, args)
        elif args.command == "agent":
            _agent(config, args)
        elif args.command == "dashboard":
            _dashboard(config, args)
        elif args.command == "housekeep":
            _housekeep(config, args)
        elif args.command == "migrate":
            _migrate(config, args)
        elif args.command == "vistafuzz":
            _vistafuzz(config, args)
        elif args.command == "doctor":
            _doctor(config)
    except PipelineError as exc:
        raise SystemExit(str(exc)) from exc


def _plan(config: dict, args: argparse.Namespace) -> None:
    pipeline = config["pipeline"]
    input_path = args.input or pipeline["input_path"]
    runs_root = args.runs_root or pipeline["runs_path"]
    lock = load_toolchain_lock(pipeline["toolchain_lock_path"])
    support_index = load_oss_fuzz_support_index(
        pipeline["oss_fuzz_index_path"], lock
    )
    summary = prepare_jobs(
        load_jsonl(input_path),
        runs_root,
        pipeline,
        lock,
        support_index,
        limit=args.limit,
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


def _status(config: dict, args: argparse.Namespace) -> None:
    value = job_status(config["pipeline"]["runs_path"], args.job_id)
    if args.json:
        print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))
        return
    print(f"repository         {value['repository']}@{value['commit']}")
    print(f"state              {value['status']} / {value['stage']}")
    print(f"fuzz target        {value['fuzz_target'] or '-'}")
    print(
        f"fuzz progress      {value['fuzz_completed_seconds']:.0f}/"
        f"{value['fuzz_budget_seconds']}s ({value['fuzz_percent']:.2f}%)"
    )
    print(f"remaining          {value['fuzz_remaining_seconds']:.0f}s")
    print(f"throughput         {value['exec_per_second']} exec/s")
    print(
        f"coverage           edges={value['coverage_edges']} / "
        f"features={value['coverage_features']}"
    )
    print(f"coverage stalled   {str(value['coverage_stalled']).lower()}")
    if value.get("adaptive_strategy"):
        print(
            f"adaptive strategy  {value['adaptive_strategy']} / "
            f"{value.get('adaptive_strategy_status') or '-'}"
        )
    print(f"corpus / crashes   {value['corpus_files']} / {value['crash_files']}")
    if value["preflight_target"]:
        print(
            f"preflight         {value['preflight_target']} / "
            f"{value['preflight_status']} / findings={value['preflight_findings']}"
        )
    if value["quartet_verdict"]:
        print(f"Quartet verdict   {value['quartet_verdict']}")
    if value["attempted_fuzz_targets"]:
        print(f"rejected targets  {', '.join(value['attempted_fuzz_targets'])}")
    if value["afl_cmplog_status"]:
        print(
            f"AFL++ CmpLog     {value['afl_cmplog_status']} / "
            f"new_corpus={value['afl_cmplog_new_corpus']} / "
            f"crashes={value['afl_cmplog_crashes']}"
        )
    if value["finding_source"]:
        print(
            f"finding route     {value['finding_source']} -> "
            f"{value['triage_artifact']}"
        )
    print(f"validated groups   {value['validated_groups']}")
    print(
        f"findings           crashes={value['total_crashes']} / "
        f"false_positive={value['false_positive_groups']} / "
        f"validation={value['validation_status'] or 'pending'}"
    )
    if value["last_error"]:
        print(f"last error         {value['last_error']}")


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


def _analyze(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    result = runner.analyze(args.job_id)
    review = result["review"]
    print(
        f"analysis complete: decision={review['decision']} "
        f"target={review['selected_fuzz_target']} "
        f"execution_ready={review['execution_ready']}"
    )


def _quartet(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    result = runner.quartet(args.job_id)
    review = result["review"]
    message = (
        f"quartet complete: verdict={review['overall_verdict']} "
        f"execution_ready={review['execution_ready']} "
        f"reach_confidence={review['reach_confidence']}"
    )
    state = result.get("state") or {}
    if state.get("status") == "target_retry_pending":
        message += f" next_target={state.get('preferred_fuzz_target')}"
    print(message)


def _generate(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    result = runner.generate(args.job_id)
    print(
        f"generation complete: target={result['fuzz_target']} "
        f"attempts={len(result['attempts'])} stage={result['state']['stage']}"
    )


def _run(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    result = runner.fuzz(args.job_id)
    print(
        f"fuzz complete: target={result['fuzz_target']} "
        f"seconds={result['elapsed_seconds']} crashes={len(result['crash_files'])}"
    )


def _afl_cmplog(config: dict, args: argparse.Namespace) -> None:
    runner = PipelineRunner(config, progress=lambda message: print(message, flush=True))
    result = runner.afl_cmplog(args.job_id)
    print(
        f"AFL++ CmpLog: status={result['status']} "
        f"target={result.get('fuzz_target', 'unknown')} "
        f"new_corpus={result.get('new_corpus_files', 0)} "
        f"crashes={len(result.get('crash_files') or [])}"
    )


def _triage(config: dict, args: argparse.Namespace) -> None:
    runner = TriageRunner(config, progress=lambda message: print(message, flush=True))
    result = runner.triage(args.job_id, use_ai=not args.no_ai)
    print(
        f"triage complete: inputs={result['input_crash_count']} "
        f"validated_groups={result['validated_group_count']} "
        f"status={result['state']['status']}"
    )


def _validate(config: dict, args: argparse.Namespace) -> None:
    runner = ValidationAgentRunner(
        config, progress=lambda message: print(message, flush=True)
    )
    result = runner.validate(args.job_id)
    print(
        f"validation complete: findings={len(result['findings'])} "
        f"status={result['state']['status']}"
    )


def _doctor(config: dict) -> None:
    pipeline = config["pipeline"]
    resources = plan_resources(pipeline)
    checks = [
        ("operating system", f"{platform.system()} {platform.release()}"),
        ("python", platform.python_version()),
        ("git", shutil.which("git") or "missing"),
        ("docker cli", shutil.which("docker") or "missing"),
        ("codex cli", shutil.which("codex") or "missing"),
        (
            "toolchain lock",
            "ok" if Path(pipeline["toolchain_lock_path"]).is_file() else "missing",
        ),
        (
            "OSS-Fuzz index",
            "ok" if Path(pipeline["oss_fuzz_index_path"]).is_file() else "missing",
        ),
        ("runs root", str(Path(pipeline["runs_path"]))),
        ("tools root", str(Path(pipeline["tools_path"]))),
        ("AI model", f"{pipeline['ai_model']} ({pipeline['ai_reasoning_effort']})"),
        (
            "architecture",
            (
                f"{resolve_host_architecture(config['architecture'])} / "
                f"{config['architecture']['mode']} / emulation disabled"
            ),
        ),
        (
            "native builder",
            str(config["architecture"]["native_builder_image"]),
        ),
        ("detected CPUs", str(resources.detected.cpu_count)),
        ("available memory", f"{resources.detected.memory_available_mb} MB"),
        ("parallel jobs", str(resources.parallel_jobs)),
        ("workers per job", str(resources.workers_per_job)),
        ("memory per job", f"{resources.container_memory_mb} MB"),
        ("fuzzer RSS limit", f"{resources.fuzzer_rss_limit_mb} MB"),
        ("resource sources", ", ".join(resources.detected.sources)),
        (
            "central monitor",
            f"every {int(config['agent']['monitor_interval_seconds'])} seconds",
        ),
        (
            "telegram alerts",
            "configured"
            if os.environ.get(str(config["agent"]["telegram_token_env"]))
            and os.environ.get(str(config["agent"]["telegram_chat_id_env"]))
            else "missing environment variables",
        ),
    ]
    daemon = _docker_server_status()
    checks.insert(2, ("docker daemon", daemon))
    for name, value in checks:
        print(f"{name:18} {value}")


def _worker(config: dict, args: argparse.Namespace) -> None:
    worker = PipelineWorker(config, progress=lambda message: print(message, flush=True))
    results = worker.run(args.max_jobs, setup_only=args.setup_only)
    if not results:
        print("worker complete: no runnable jobs")
        return
    for result in results:
        print(
            f"worker result: job_id={result.job_id} action={result.action} "
            f"status={result.status} stage={result.stage} error={result.error}"
        )


def _agent(config: dict, args: argparse.Namespace) -> None:
    agent = CentralAgent(config, progress=lambda message: print(message, flush=True))
    if args.test_telegram:
        delivered, detail = agent.test_telegram()
        print(f"telegram test: delivered={str(delivered).lower()} detail={detail}")
        if not delivered:
            raise PipelineError(f"telegram test failed: {detail}")
        return
    def stop_agent(_signum, _frame):
        agent.stop()

    previous_term = signal.signal(signal.SIGTERM, stop_agent)
    try:
        result = agent.run(
            max_batches=args.max_batches,
            once=args.once,
            exit_when_idle=args.exit_when_idle,
            discovery=not args.no_discovery,
        )
    except KeyboardInterrupt:
        agent.stop()
        print("central agent stopped", flush=True)
        return
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    print(
        f"central agent complete: status={result.get('status')} "
        f"batches={result.get('completed_batches', 0)} "
        f"state={result.get('state_path')}"
    )


def _dashboard(config: dict, args: argparse.Namespace) -> None:
    interval = args.interval or int(config["pipeline"]["dashboard_interval_seconds"])
    if interval < 1:
        raise PipelineError("dashboard interval must be positive")
    while True:
        value = pipeline_overview(config["pipeline"]["runs_path"])
        if args.json:
            print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))
        else:
            print(
                f"jobs={value['job_count']} disk={value['total_disk_bytes']} "
                f"states={value['status_counts']}"
            )
            print(
                "STATUS                 STAGE                    PROGRESS   EXEC/S     COV  "
                "CRASH  VALIDATION       TARGET / REPOSITORY"
            )
            for item in value["jobs"]:
                print(
                    f"{str(item['status']):22.22} {str(item['stage']):24.24} "
                    f"{item['fuzz_percent']:7.2f}% {item['exec_per_second']:7d} "
                    f"{item['coverage_edges']:7d} "
                    f"{item['total_crashes']:6d} "
                    f"{str(item['validation_status'] or '-'):16.16} "
                    f"{item['fuzz_target'] or '-'} / {item['repository']}"
                )
        if not args.watch:
            return
        time.sleep(interval)


def _housekeep(config: dict, args: argparse.Namespace) -> None:
    value = Housekeeper(config).run(args.job_id)
    if args.json:
        print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))
        return
    for item in value["jobs"]:
        print(
            f"{item['job_id']}: {item['before_bytes']} -> {item['after_bytes']} bytes, "
            f"removed={item['removed_files']}, over_limit={item['over_limit']}"
        )
    if value["removed_orphan_containers"]:
        print("removed containers: " + ", ".join(value["removed_orphan_containers"]))


def _migrate(config: dict, args: argparse.Namespace) -> None:
    value = migrate_runs(config["pipeline"]["runs_path"], dry_run=args.dry_run)
    print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


def _vistafuzz(config: dict, args: argparse.Namespace) -> None:
    adapter = VistaFuzzAdapter(config)
    value = adapter.smoke(args.smoke_seconds) if args.smoke_seconds else adapter.inspect()
    print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


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
