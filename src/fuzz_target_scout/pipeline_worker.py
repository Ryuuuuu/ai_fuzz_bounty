from __future__ import annotations

import fcntl
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .pipeline import PipelineError, utc_now
from .pipeline_runner import PipelineRunner, STAGE_ORDER


MANUAL_STATUSES = {
    "quartet_review_required",
    "manual_review",
    "triage_pending",
    "running",
    "complete",
    "exhausted",
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
        self.runner = PipelineRunner(config, progress=self.progress)

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
            while max_jobs == 0 or len(results) < max_jobs:
                job_id = self._next_job(attempted)
                if not job_id:
                    break
                attempted.add(job_id)
                results.append(self._advance(job_id, setup_only=setup_only))
        return results

    def _next_job(self, attempted: set[str]) -> str:
        candidates: list[tuple[str, str]] = []
        for state_path in self.runs_root.glob("*/state.json"):
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            job_id = str(state.get("job_id") or state_path.parent.name)
            status = str(state.get("status") or "")
            stage = str(state.get("stage") or "")
            if job_id in attempted or status in MANUAL_STATUSES or stage == "triage":
                continue
            created = str(state.get("created_at") or "")
            candidates.append((created, job_id))
        candidates.sort(key=lambda item: (item[0], item[1]))
        return candidates[0][1] if candidates else ""

    def _advance(self, job_id: str, *, setup_only: bool) -> WorkerResult:
        action = "none"
        try:
            for _ in range(30):
                state = self._state(job_id)
                stage = str(state.get("stage") or "")
                status = str(state.get("status") or "")
                self.progress(f"worker {job_id}: status={status} stage={stage}")
                if stage in STAGE_ORDER:
                    action = "prepare"
                    self.runner.prepare(job_id)
                elif stage == "integration":
                    action = "integrate"
                    self.runner.integrate(job_id)
                elif stage == "build":
                    action = "build"
                    self.runner.build(job_id)
                elif stage == "smoke":
                    action = "smoke"
                    self.runner.smoke(job_id)
                elif stage == "quartet_gate":
                    if not self._artifact(job_id, "probe-run.json").is_file():
                        action = "probe"
                        self.runner.probe(job_id)
                    else:
                        action = "quartet"
                        self.runner.quartet(job_id)
                elif stage == "coverage_analysis":
                    action = "analyze"
                    self.runner.analyze(job_id)
                elif stage == "fuzzing":
                    if status in {"harness_work_pending", "generation_failed"}:
                        cycles = int((state.get("attempts") or {}).get("harness_generation", 0))
                        if cycles >= int(self.pipeline["max_generation_cycles"]):
                            return WorkerResult(
                                job_id, status, stage, "manual_review", "generation cycle limit reached"
                            )
                        action = "generate"
                        self.runner.generate(job_id)
                    elif status == "ready":
                        if setup_only:
                            return WorkerResult(job_id, status, stage, "ready")
                        action = "fuzz"
                        self.runner.fuzz(job_id)
                    else:
                        return WorkerResult(job_id, status, stage, "needs_attention")
                elif stage == "triage":
                    return WorkerResult(job_id, status, stage, "triage_pending")
                else:
                    raise PipelineError(f"worker does not understand stage: {stage}")
            raise PipelineError("worker exceeded the state transition limit")
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
            state["status"] = "worker_failed"
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
