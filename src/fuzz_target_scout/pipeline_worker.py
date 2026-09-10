from __future__ import annotations

import fcntl
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .pipeline import PipelineError, PipelineInterrupted, utc_now
from .pipeline_runner import PipelineRunner, STAGE_ORDER
from .triage import TriageRunner
from .operations import Housekeeper
from .resources import ResourceAllocation, plan_resources
from .validation_agent import ValidationAgentRunner


MANUAL_STATUSES = {
    "quartet_review_required",
    "manual_review",
    "complete",
    "exhausted",
    "unsupported_integration",
    "ready_for_human",
    "triage_review_required",
    "resource_limit_required",
    "validation_review_required",
}


@dataclass(slots=True)
class WorkerResult:
    job_id: str
    status: str
    stage: str
    action: str
    error: str = ""


class PipelineWorker:
    def __init__(self, config: dict[str, Any], progress=None):
        self.config = config
        self.pipeline = config["pipeline"]
        self.runs_root = Path(self.pipeline["runs_path"])
        self.progress = progress or (lambda _: None)
        self.stop_event = threading.Event()
        self.runner = PipelineRunner(
            config, progress=self.progress, cancel_event=self.stop_event
        )
        self.triage_runner = TriageRunner(config, progress=self.progress)
        self.validation_runner = ValidationAgentRunner(config, progress=self.progress)
        self.housekeeper = Housekeeper(config)
        self._non_fuzz_lock = threading.Lock()

    def stop(self) -> None:
        self.stop_event.set()

    def run(self, max_jobs: int, *, setup_only: bool = False) -> list[WorkerResult]:
        if max_jobs < 0:
            raise PipelineError("max_jobs cannot be negative")
        self.runs_root.mkdir(parents=True, exist_ok=True)
        lock_path = self.runs_root / ".pipeline-worker.lock"
        results: list[WorkerResult] = []
        attempted: set[str] = set()
        with lock_path.open("w", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise PipelineError("another fuzz pipeline worker is already running") from exc
            housekeeper = getattr(self, "housekeeper", None)
            if housekeeper is not None:
                housekeeper.run()
            while max_jobs == 0 or len(results) < max_jobs:
                requested_jobs = (
                    None if max_jobs == 0 else max_jobs - len(results)
                )
                allocation = plan_resources(
                    self.pipeline, requested_jobs=requested_jobs
                )
                remaining = allocation.parallel_jobs
                job_ids = self._next_jobs(attempted, remaining)
                if not job_ids:
                    break
                attempted.update(job_ids)
                batch_allocation = plan_resources(
                    self.pipeline,
                    requested_jobs=len(job_ids),
                    snapshot=allocation.detected,
                )
                self.progress(
                    "resource plan: "
                    f"jobs={len(job_ids)} workers/job={batch_allocation.workers_per_job} "
                    f"memory/job={batch_allocation.container_memory_mb}MB"
                )
                ready_jobs: list[str] = []
                for job_id in job_ids:
                    prepared = self._advance(
                        job_id,
                        setup_only=True,
                        allocation=batch_allocation,
                    )
                    if prepared.action == "ready" and not setup_only:
                        ready_jobs.append(job_id)
                    else:
                        results.append(prepared)
                if ready_jobs:
                    run_allocation = plan_resources(
                        self.pipeline,
                        requested_jobs=len(ready_jobs),
                        snapshot=allocation.detected,
                    )
                    with ThreadPoolExecutor(
                        max_workers=len(ready_jobs), thread_name_prefix="fuzz-job"
                    ) as executor:
                        futures = [
                            executor.submit(
                                self._advance,
                                job_id,
                                setup_only=False,
                                allocation=run_allocation,
                            )
                            for job_id in ready_jobs
                        ]
                        results.extend(future.result() for future in futures)
                if housekeeper is not None:
                    for job_id in job_ids:
                        housekeeper.run(job_id)
        return results

    def _next_job(self, attempted: set[str]) -> str:
        jobs = self._next_jobs(attempted, 1)
        return jobs[0] if jobs else ""

    def _next_jobs(self, attempted: set[str], limit: int) -> list[str]:
        if limit < 1:
            return []
        candidates: list[tuple[str, str]] = []
        for state_path in self.runs_root.glob("*/state.json"):
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            job_id = str(state.get("job_id") or state_path.parent.name)
            status = str(state.get("status") or "")
            stage = str(state.get("stage") or "")
            if job_id in attempted or status in MANUAL_STATUSES or stage == "complete":
                continue
            created = str(state.get("created_at") or "")
            candidates.append((created, job_id))
        candidates.sort(key=lambda item: (item[0], item[1]))
        return [job_id for _, job_id in candidates[:limit]]

    def _advance(
        self,
        job_id: str,
        *,
        setup_only: bool,
        allocation: ResourceAllocation | None = None,
    ) -> WorkerResult:
        action = "none"
        try:
            for _ in range(100):
                state = self._state(job_id)
                stage = str(state.get("stage") or "")
                status = str(state.get("status") or "")
                self.progress(f"worker {job_id}: status={status} stage={stage}")
                if status in MANUAL_STATUSES:
                    return WorkerResult(job_id, status, stage, "needs_attention")
                if stage in STAGE_ORDER[:-1]:
                    action = "prepare"
                    self._serialized(self.runner.prepare, job_id)
                elif stage == "integration":
                    action = "integrate"
                    self._serialized(self.runner.integrate, job_id)
                elif stage == "build":
                    action = "build"
                    self._serialized(self.runner.build, job_id)
                elif stage == "smoke":
                    action = "smoke"
                    self._serialized(self.runner.smoke, job_id)
                elif stage == "quartet_gate":
                    if status == "quartet_repair_pending":
                        action = "quartet_repair"
                        self._serialized(self.runner.repair_quartet_harness, job_id)
                    elif not self._artifact(job_id, "probe-run.json").is_file():
                        action = "probe"
                        self._serialized(self.runner.probe, job_id)
                    else:
                        action = "quartet"
                        self._serialized(self.runner.quartet, job_id)
                elif stage == "coverage_analysis":
                    action = "analyze"
                    self._serialized(self.runner.analyze, job_id)
                elif stage == "fuzzing":
                    if status == "afl_cmplog_pending":
                        if setup_only:
                            return WorkerResult(job_id, status, stage, "ready")
                        action = "afl_cmplog"
                        self._serialized(self._run_afl, job_id, allocation)
                    elif status in {"harness_work_pending", "generation_failed"}:
                        cycles = int((state.get("attempts") or {}).get("harness_generation", 0))
                        if cycles >= int(self.pipeline["max_generation_cycles"]):
                            return WorkerResult(
                                job_id, status, stage, "manual_review", "generation cycle limit reached"
                            )
                        action = "generate"
                        self._serialized(self.runner.generate, job_id)
                    elif status in {"ready", "running", "interrupted", "worker_failed"}:
                        if setup_only:
                            return WorkerResult(job_id, status, stage, "ready")
                        action = "fuzz"
                        self._run_fuzz(job_id, allocation)
                    else:
                        return WorkerResult(job_id, status, stage, "needs_attention")
                elif stage == "triage":
                    action = "triage"
                    self._serialized(self._run_triage, job_id, allocation)
                elif stage == "validation":
                    action = "validate"
                    result = self._serialized(
                        self._run_validation, job_id, allocation
                    )
                    final_state = result["state"]
                    return WorkerResult(
                        job_id,
                        str(final_state["status"]),
                        str(final_state["stage"]),
                        action,
                    )
                else:
                    raise PipelineError(f"worker does not understand stage: {stage}")
            raise PipelineError("worker exceeded the state transition limit")
        except PipelineInterrupted as exc:
            state = self._state(job_id)
            return WorkerResult(
                job_id,
                str(state.get("status") or "interrupted"),
                str(state.get("stage") or "unknown"),
                "interrupted",
                str(exc)[:2000],
            )
        except Exception as exc:
            self._record_worker_error(job_id, exc)
            state = self._state(job_id)
            return WorkerResult(
                job_id,
                str(state.get("status") or "worker_failed"),
                str(state.get("stage") or "unknown"),
                action,
                str(exc)[:2000],
            )

    def _serialized(self, function, *args, **kwargs):
        lock = getattr(self, "_non_fuzz_lock", None)
        if lock is None:
            return function(*args, **kwargs)
        with lock:
            return function(*args, **kwargs)

    def _run_fuzz(
        self, job_id: str, allocation: ResourceAllocation | None
    ) -> dict[str, Any]:
        if allocation is None:
            return self.runner.fuzz(job_id)
        return self.runner.fuzz(job_id, allocation=allocation)

    def _run_afl(
        self, job_id: str, allocation: ResourceAllocation | None
    ) -> dict[str, Any]:
        if allocation is None:
            return self.runner.afl_cmplog(job_id)
        return self.runner.afl_cmplog(job_id, allocation=allocation)

    def _run_triage(
        self, job_id: str, allocation: ResourceAllocation | None
    ) -> dict[str, Any]:
        if allocation is None:
            return self.triage_runner.triage(job_id, use_ai=False)
        return self.triage_runner.triage(
            job_id, use_ai=False, allocation=allocation
        )

    def _run_validation(
        self, job_id: str, allocation: ResourceAllocation | None
    ) -> dict[str, Any]:
        if allocation is None:
            return self.validation_runner.validate(job_id)
        return self.validation_runner.validate(job_id, allocation=allocation)

    def _state(self, job_id: str) -> dict[str, Any]:
        path = self.runs_root / job_id / "state.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PipelineError(f"could not read worker state for {job_id}") from exc
        if not isinstance(value, dict):
            raise PipelineError(f"invalid worker state for {job_id}")
        return value

    def _artifact(self, job_id: str, name: str) -> Path:
        return self.runs_root / job_id / "artifacts" / name

    def _record_worker_error(self, job_id: str, exc: Exception) -> None:
        path = self.runs_root / job_id / "state.json"
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            if state.get("status") != "interrupted":
                state["status"] = "worker_failed"
            attempts = state.setdefault("attempts", {})
            attempts["worker_failures"] = int(attempts.get("worker_failures", 0)) + 1
            maximum = int(getattr(self, "pipeline", {}).get("max_stage_failures", 3))
            if attempts["worker_failures"] >= maximum:
                state["status"] = "manual_review"
            state["last_error"] = str(exc)[:2000]
            state["updated_at"] = utc_now()
            temporary = path.with_suffix(".json.tmp")
            temporary.write_text(
                json.dumps(state, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            temporary.replace(path)
        except (OSError, json.JSONDecodeError):
            return
