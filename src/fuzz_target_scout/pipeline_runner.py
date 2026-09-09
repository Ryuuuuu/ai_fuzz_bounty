from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any, Callable

from .coverage_analysis import (
    CodexCoverageReviewer,
    IntrospectorClient,
    analysis_record,
    build_coverage_evidence,
    deterministic_review,
    refresh_evidence_hash,
)
from .github import GitHubClient
from .harness_generation import (
    extract_harness_code,
    generation_prompt,
    generation_record,
    invoke_oss_fuzz_gen_adapter,
    select_generation_candidate,
    source_context,
    validate_generated_harness,
)
from .pipeline import COMMIT_PATTERN, PipelineError, utc_now
from .policy import PolicyVerifier
from .quartet_gate import (
    CodexQuartetReviewer,
    build_quartet_evidence,
    find_harness_source,
    quartet_record,
)


Progress = Callable[[str], None]
JOB_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,160}$")
GITHUB_REPOSITORY_PATTERN = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$"
)
STAGE_ORDER = ("policy_recheck", "source_checkout", "tool_sync", "integration")


class PipelineRunner:
    def __init__(self, config: dict[str, Any], progress: Progress | None = None):
        self.config = config
        self.pipeline = config["pipeline"]
        self.progress = progress or (lambda _: None)
        self.runs_root = Path(self.pipeline["runs_path"])
        self.tools_root = Path(self.pipeline["tools_path"])
        self.github = GitHubClient(config["github"])
        self.policy = PolicyVerifier(
            config["policy"]["catalog_path"],
            int(config["policy"]["max_catalog_age_days"]),
        )

    def prepare(self, job_id: str, until: str = "integration") -> dict[str, Any]:
        if until not in STAGE_ORDER:
            raise PipelineError(f"unsupported preparation boundary: {until}")
        job_dir = self._job_dir(job_id)
        job = self._read_json(job_dir / "job.json")
        state_path = job_dir / "state.json"
        state = self._read_json(state_path)
        (job_dir / "validation").mkdir(exist_ok=True)

        while state.get("stage") != until:
            stage = str(state.get("stage") or "")
            if stage not in STAGE_ORDER:
                raise PipelineError(f"job {job_id} has invalid stage: {stage}")
            try:
                if stage == "policy_recheck":
                    self._recheck_policy(job_dir, job)
                    next_stage = "source_checkout"
                elif stage == "source_checkout":
                    self._checkout_source(job_dir, job)
                    next_stage = "tool_sync"
                elif stage == "tool_sync":
                    self._sync_required_tools(job_dir, job)
                    next_stage = "integration"
                else:
                    break
            except Exception as exc:
                state["status"] = "failed"
                state["last_error"] = str(exc)[:2000]
                state["updated_at"] = utc_now()
                self._write_json(state_path, state)
                if isinstance(exc, PipelineError):
                    raise
                raise PipelineError(f"{stage} failed: {exc}") from exc
            state["status"] = "prepared" if next_stage == "integration" else "preparing"
            state["stage"] = next_stage
            state["last_error"] = None
            state["updated_at"] = utc_now()
            state.setdefault("attempts", {})[stage] = (
                int(state.setdefault("attempts", {}).get(stage, 0)) + 1
            )
            self._write_json(state_path, state)
            self.progress(f"{job_id}: {stage} -> {next_stage}")
        return state

    def integrate(self, job_id: str) -> dict[str, Any]:
        return self._single_stage(
            job_id,
            expected="integration",
            next_stage="build",
            next_status="integrated",
            action=self._prepare_integration,
        )

    def build(self, job_id: str) -> dict[str, Any]:
        return self._single_stage(
            job_id,
            expected="build",
            next_stage="smoke",
            next_status="built",
            action=self._build_fuzzers,
        )

    def smoke(self, job_id: str) -> dict[str, Any]:
        return self._single_stage(
            job_id,
            expected="smoke",
            next_stage="quartet_gate",
            next_status="quartet_pending",
            action=self._smoke_fuzzer,
        )

    def probe(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        job = self._read_json(job_dir / "job.json")
        state = self._read_json(job_dir / "state.json")
        if state.get("stage") not in {"quartet_gate", "coverage_analysis", "fuzzing"}:
            raise PipelineError(
                f"job {job_id} is at {state.get('stage')}, expected coverage_analysis"
            )
        return self._fuzz_session(
            job_dir,
            job,
            seconds=int(self.pipeline["probe_seconds"]),
            workers=min(2, int(self.pipeline["parallel_workers"])),
            label="probe",
        )

    def quartet(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        job = self._read_json(job_dir / "job.json")
        state_path = job_dir / "state.json"
        state = self._read_json(state_path)
        if state.get("stage") not in {"quartet_gate", "fuzzing"}:
            raise PipelineError(
                f"job {job_id} is at {state.get('stage')}, expected quartet_gate"
            )
        artifact_path = job_dir / "artifacts" / "quartet-review.json"
        if artifact_path.is_file():
            return self._read_json(artifact_path)
        probe_path = job_dir / "artifacts" / "probe-run.json"
        if not probe_path.is_file():
            raise PipelineError("run a probe before the Quartet gate")
        build = self._read_json(job_dir / "artifacts" / "build-manifest.json")
        smoke = self._read_json(job_dir / "artifacts" / "smoke.json")
        probe = self._read_json(probe_path)
        quartet_root = self.tools_root / "quartetfuzz"
        facts, ai_evidence = build_quartet_evidence(
            job_dir, job, build, smoke, probe, quartet_root
        )
        review, usage = CodexQuartetReviewer(self.pipeline).review(ai_evidence)
        record = quartet_record(facts, review, usage)
        self._write_json(artifact_path, record)
        ready = bool(record["review"]["execution_ready"])
        if ready and (job_dir / "artifacts" / "coverage-plan.json").is_file():
            state["stage"] = "fuzzing"
            state["status"] = "ready"
        elif ready:
            state["stage"] = "coverage_analysis"
            state["status"] = "analysis_pending"
        else:
            state["stage"] = "quartet_gate"
            state["status"] = "quartet_review_required"
        state["last_error"] = None
        state["updated_at"] = utc_now()
        state.setdefault("attempts", {})["quartet_gate"] = (
            int(state.setdefault("attempts", {}).get("quartet_gate", 0)) + 1
        )
        self._write_json(state_path, state)
        record["state"] = state
        return record

    def analyze(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        job = self._read_json(job_dir / "job.json")
        state_path = job_dir / "state.json"
        state = self._read_json(state_path)
        if state.get("stage") not in {"coverage_analysis", "fuzzing"}:
            raise PipelineError(
                f"job {job_id} is at {state.get('stage')}, expected coverage_analysis"
            )
        quartet_path = job_dir / "artifacts" / "quartet-review.json"
        if not quartet_path.is_file():
            raise PipelineError("the Quartet gate is required before coverage analysis")
        quartet = self._read_json(quartet_path)
        if not bool((quartet.get("review") or {}).get("execution_ready")):
            raise PipelineError("the Quartet gate requires review before coverage analysis")
        artifact_path = job_dir / "artifacts" / "coverage-plan.json"
        if artifact_path.is_file():
            return self._read_json(artifact_path)
        probe_path = job_dir / "artifacts" / "probe-run.json"
        if not probe_path.is_file():
            raise PipelineError("run a probe before coverage analysis")
        build = self._read_json(job_dir / "artifacts" / "build-manifest.json")
        probe = self._read_json(probe_path)
        project = str(build["oss_fuzz_project"])
        client = IntrospectorClient(
            str(self.pipeline["introspector_endpoint"]),
            int(self.pipeline["introspector_timeout_seconds"]),
        )
        candidates, errors = client.candidates(project)
        evidence = build_coverage_evidence(
            job_dir,
            job,
            build,
            probe,
            candidates,
            max_candidates=int(self.pipeline["coverage_candidate_limit"]),
        )
        evidence["quartet_review"] = {
            "overall_verdict": (quartet.get("review") or {}).get("overall_verdict"),
            "execution_ready": (quartet.get("review") or {}).get("execution_ready"),
            "target_symbols": (quartet.get("review") or {}).get("target_symbols", []),
            "reach_confidence": (quartet.get("review") or {}).get("reach_confidence"),
        }
        refresh_evidence_hash(evidence)
        review = deterministic_review(evidence, errors)
        reviewer = "deterministic_gate"
        usage = {"input_tokens": 0, "cached_tokens": 0, "output_tokens": 0}
        if review is None:
            review, usage = CodexCoverageReviewer(self.pipeline).review(evidence)
            reviewer = "codex_cli"
        record = analysis_record(evidence, review, usage, errors, reviewer=reviewer)
        self._write_json(artifact_path, record)
        state["stage"] = "fuzzing"
        state["status"] = (
            "ready" if record["review"]["execution_ready"] else "harness_work_pending"
        )
        state["last_error"] = None
        state["updated_at"] = utc_now()
        state.setdefault("attempts", {})["coverage_analysis"] = (
            int(state.setdefault("attempts", {}).get("coverage_analysis", 0)) + 1
        )
        self._write_json(state_path, state)
        record["state"] = state
        return record

    def generate(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        job = self._read_json(job_dir / "job.json")
        state_path = job_dir / "state.json"
        state = self._read_json(state_path)
        if state.get("stage") != "fuzzing" or state.get("status") not in {
            "harness_work_pending",
            "generation_failed",
        }:
            raise PipelineError("job does not currently require harness generation")
        plan = self._read_json(job_dir / "artifacts" / "coverage-plan.json")
        candidate = select_generation_candidate(plan)
        build = self._read_json(job_dir / "artifacts" / "build-manifest.json")
        fuzz_target = str((plan.get("review") or {})["selected_fuzz_target"])
        if fuzz_target not in build.get("fuzz_targets", []):
            raise PipelineError("generation plan selected an unknown fuzz target")
        source_root = job_dir / "source"
        evidence_harness = find_harness_source(source_root, fuzz_target)
        relative_harness = evidence_harness.relative_to(source_root)
        build_harness = job_dir / "build-source" / relative_harness
        if not build_harness.is_file():
            raise PipelineError("build worktree does not contain the selected harness")
        original_code = evidence_harness.read_text(encoding="utf-8", errors="replace")
        if build_harness.read_text(encoding="utf-8", errors="replace") != original_code:
            raise PipelineError("build harness differs from the pinned evidence source")
        context = source_context(source_root, candidate)
        expected_tools = {
            str(item.get("name")): str(item.get("commit"))
            for item in (job.get("route") or {}).get("required_tools") or []
        }
        oss_fuzz_gen = self.tools_root / "oss-fuzz-gen"
        actual_tool_commit = self._capture(
            ["git", "-C", str(oss_fuzz_gen), "rev-parse", "HEAD"]
        )
        if actual_tool_commit.casefold() != expected_tools.get("oss-fuzz-gen", "").casefold():
            raise PipelineError("OSS-Fuzz-Gen checkout no longer matches the work order")

        generation_root = job_dir / "integration" / "generated" / str(time.time_ns())
        generation_root.mkdir(parents=True)
        attempts: list[dict[str, Any]] = []
        prior_code = ""
        build_error = ""
        max_attempts = int((job.get("ai") or {})["max_harness_attempts"])
        final_validation: dict[str, Any] = {}
        try:
            for attempt in range(1, max_attempts + 1):
                code = ""
                usage: dict[str, int] = {}
                prompt = generation_prompt(
                    project=str(build["oss_fuzz_project"]),
                    language=str((job.get("source") or {}).get("language") or "C++"),
                    fuzz_target=fuzz_target,
                    candidate=candidate,
                    context=context,
                    existing_harness=original_code,
                    prior_code=prior_code,
                    build_error=build_error,
                )
                attempt_dir = generation_root / f"attempt-{attempt}"
                try:
                    response, usage = invoke_oss_fuzz_gen_adapter(
                        self.pipeline, prompt, attempt_dir
                    )
                    code = extract_harness_code(response)
                    validation = validate_generated_harness(code, candidate)
                    build_harness.write_text(code, encoding="utf-8")
                    self._build_fuzzers(job_dir, job)
                except PipelineError as exc:
                    build_error = str(exc)
                    build_log = job_dir / "logs" / "oss-fuzz-build.log"
                    if build_log.is_file():
                        build_error += "\n" + build_log.read_text(
                            encoding="utf-8", errors="replace"
                        )[-8000:]
                    attempts.append(
                        {
                            "attempt": attempt,
                            "success": False,
                            "error": str(exc)[:2000],
                            "usage": usage,
                        }
                    )
                    prior_code = code
                    if attempt == max_attempts:
                        raise PipelineError(
                            f"harness generation failed after {max_attempts} attempts: {exc}"
                        ) from exc
                    continue
                attempts.append(
                    {
                        "attempt": attempt,
                        "success": True,
                        "error": "",
                        "usage": usage,
                    }
                )
                final_validation = validation
                break
        except Exception as exc:
            build_harness.write_text(original_code, encoding="utf-8")
            state["status"] = "generation_failed"
            state["last_error"] = str(exc)[:2000]
            state["updated_at"] = utc_now()
            self._write_json(state_path, state)
            if isinstance(exc, PipelineError):
                raise
            raise PipelineError(f"harness generation failed: {exc}") from exc

        manifest_path = job_dir / "artifacts" / "build-manifest.json"
        manifest = self._read_json(manifest_path)
        manifest["generated_fuzz_target"] = fuzz_target
        manifest["generated_harness_path"] = str(build_harness)
        manifest["generated_harness_sha256"] = final_validation["sha256"]
        self._write_json(manifest_path, manifest)
        record = generation_record(
            candidate=candidate,
            fuzz_target=fuzz_target,
            harness_path=relative_harness.as_posix(),
            validation=final_validation,
            attempts=attempts,
            oss_fuzz_gen_commit=actual_tool_commit,
        )
        self._archive_pre_generation_results(job_dir, fuzz_target)
        self._write_json(job_dir / "artifacts" / "harness-generation.json", record)
        state["stage"] = "smoke"
        state["status"] = "generated"
        state["last_error"] = None
        state["updated_at"] = utc_now()
        state.setdefault("attempts", {})["harness_generation"] = (
            int(state.setdefault("attempts", {}).get("harness_generation", 0)) + 1
        )
        self._write_json(state_path, state)
        record["state"] = state
        return record

    def fuzz(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        job = self._read_json(job_dir / "job.json")
        state_path = job_dir / "state.json"
        state = self._read_json(state_path)
        if state.get("stage") != "fuzzing":
            raise PipelineError(
                f"job {job_id} is at {state.get('stage')}, expected fuzzing"
            )
        quartet_path = job_dir / "artifacts" / "quartet-review.json"
        if not quartet_path.is_file():
            raise PipelineError("the Quartet gate is required before a full fuzz run")
        quartet = self._read_json(quartet_path)
        if not bool((quartet.get("review") or {}).get("execution_ready")):
            raise PipelineError("the Quartet gate did not approve this harness")
        plan_path = job_dir / "artifacts" / "coverage-plan.json"
        if not plan_path.is_file():
            raise PipelineError("coverage analysis is required before a full fuzz run")
        plan = self._read_json(plan_path)
        if not bool((plan.get("review") or {}).get("execution_ready")):
            decision = (plan.get("review") or {}).get("decision", "unknown")
            raise PipelineError(
                f"coverage plan requires harness work before the full run: {decision}"
            )
        state["status"] = "running"
        state["updated_at"] = utc_now()
        state["fuzz_started_at"] = state.get("fuzz_started_at") or utc_now()
        self._write_json(state_path, state)
        try:
            result = self._fuzz_session(
                job_dir,
                job,
                seconds=int((job.get("budgets") or {})["fuzz_seconds"]),
                workers=int((job.get("execution") or {})["parallel_workers"]),
                label="fuzz",
            )
        except Exception as exc:
            state["status"] = "failed"
            state["last_error"] = str(exc)[:2000]
            state["updated_at"] = utc_now()
            self._write_json(state_path, state)
            if isinstance(exc, PipelineError):
                raise
            raise PipelineError(f"fuzzing failed: {exc}") from exc
        state["status"] = "triage_pending"
        state["stage"] = "triage"
        state["last_error"] = None
        state["fuzz_completed_at"] = utc_now()
        state["updated_at"] = utc_now()
        state.setdefault("attempts", {})["fuzzing"] = (
            int(state.setdefault("attempts", {}).get("fuzzing", 0)) + 1
        )
        self._write_json(state_path, state)
        result["state"] = state
        return result

    def _single_stage(
        self,
        job_id: str,
        *,
        expected: str,
        next_stage: str,
        next_status: str,
        action: Callable[[Path, dict[str, Any]], None],
    ) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        job = self._read_json(job_dir / "job.json")
        state_path = job_dir / "state.json"
        state = self._read_json(state_path)
        if state.get("stage") != expected:
            raise PipelineError(
                f"job {job_id} is at {state.get('stage')}, expected {expected}"
            )
        try:
            action(job_dir, job)
        except Exception as exc:
            state["status"] = "failed"
            state["last_error"] = str(exc)[:2000]
            state["updated_at"] = utc_now()
            self._write_json(state_path, state)
            if isinstance(exc, PipelineError):
                raise
            raise PipelineError(f"{expected} failed: {exc}") from exc
        state["status"] = next_status
        state["stage"] = next_stage
        state["last_error"] = None
        state["updated_at"] = utc_now()
        state.setdefault("attempts", {})[expected] = (
            int(state.setdefault("attempts", {}).get(expected, 0)) + 1
        )
        self._write_json(state_path, state)
        self.progress(f"{job_id}: {expected} -> {next_stage}")
        return state

    def _recheck_policy(self, job_dir: Path, job: dict[str, Any]) -> None:
        repository = str((job.get("source") or {}).get("repository") or "")
        expected = job.get("authorization") or {}
        repo = self.github.get_repository(repository)
        if repo is None:
            raise PipelineError(f"repository is no longer available: {repository}")
        repo = self.github.load_security_policy(repo)
        current = self.policy.verify(repo)
        if current.status != "verified":
            raise PipelineError(
                f"bounty policy is no longer verified: {repository} ({current.status})"
            )
        expected_program = str(expected.get("program_url") or "").rstrip("/")
        current_program = str(current.program_url or "").rstrip("/")
        if not expected_program or current_program != expected_program:
            raise PipelineError(
                "bug-bounty program URL changed; a new scout review is required"
            )
        record = {
            "schema_version": 1,
            "repository": repository,
            "checked_at": utc_now(),
            "status": current.status,
            "confidence": current.confidence,
            "source": current.source,
            "program_url": current.program_url,
            "security_url": repo.security_url,
            "security_sha256": hashlib.sha256(
                repo.security_text.encode("utf-8")
            ).hexdigest(),
        }
        self._write_json(job_dir / "artifacts" / "authorization-recheck.json", record)

    def _checkout_source(self, job_dir: Path, job: dict[str, Any]) -> None:
        source = job.get("source") or {}
        repository = str(source.get("repository") or "")
        url = str(source.get("repository_url") or "").rstrip("/")
        expected_url = f"https://github.com/{repository}"
        if url.removesuffix(".git") != expected_url:
            raise PipelineError("repository URL does not match the work-order repository")
        if not GITHUB_REPOSITORY_PATTERN.fullmatch(url):
            raise PipelineError(f"unsupported repository URL: {url}")
        commit = str(source.get("commit") or "").lower()
        if not COMMIT_PATTERN.fullmatch(commit):
            raise PipelineError("work order does not contain a pinned commit")

        checkout = job_dir / "source"
        log_path = job_dir / "logs" / "source-checkout.log"
        if checkout.exists():
            if not (checkout / ".git").exists():
                raise PipelineError(f"existing source directory is not a Git checkout: {checkout}")
        else:
            checkout.mkdir()
            self._run(["git", "init", "--quiet", str(checkout)], log_path)
            self._run(
                ["git", "-C", str(checkout), "remote", "add", "origin", url + ".git"],
                log_path,
            )
            self._run(
                [
                    "git",
                    "-C",
                    str(checkout),
                    "fetch",
                    "--depth",
                    "1",
                    "origin",
                    commit,
                ],
                log_path,
                timeout=int(self.pipeline["setup_timeout_seconds"]),
            )
            self._run(
                ["git", "-C", str(checkout), "checkout", "--detach", "FETCH_HEAD"],
                log_path,
            )
        actual = self._capture(["git", "-C", str(checkout), "rev-parse", "HEAD"])
        if actual.casefold() != commit.casefold():
            raise PipelineError(f"checkout mismatch: expected {commit}, got {actual}")
        self._write_json(
            job_dir / "artifacts" / "source-checkout.json",
            {
                "schema_version": 1,
                "repository": repository,
                "repository_url": url,
                "commit": actual,
                "checked_out_at": utc_now(),
            },
        )

    def _sync_required_tools(self, job_dir: Path, job: dict[str, Any]) -> None:
        required = (job.get("route") or {}).get("required_tools") or []
        if not required:
            raise PipelineError("work order has no required tools")
        self.tools_root.mkdir(parents=True, exist_ok=True)
        synced: list[dict[str, str]] = []
        for tool in required:
            synced.append(self._sync_tool(job_dir, tool))
        self._write_json(
            job_dir / "artifacts" / "toolchain.json",
            {"schema_version": 1, "synced_at": utc_now(), "tools": synced},
        )

    def _sync_tool(self, job_dir: Path, tool: dict[str, Any]) -> dict[str, str]:
        name = str(tool.get("name") or "")
        url = str(tool.get("url") or "")
        commit = str(tool.get("commit") or "").lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,60}", name):
            raise PipelineError(f"invalid tool name: {name}")
        if not GITHUB_REPOSITORY_PATTERN.fullmatch(url):
            raise PipelineError(f"unsupported tool URL: {url}")
        if not COMMIT_PATTERN.fullmatch(commit):
            raise PipelineError(f"tool commit is not pinned: {name}")
        destination = self.tools_root / name
        log_path = job_dir / "logs" / f"tool-{name}.log"
        if destination.exists() and not (destination / ".git").exists():
            raise PipelineError(f"tool directory is not a Git checkout: {destination}")
        if not destination.exists():
            destination.mkdir()
            self._run(["git", "init", "--quiet", str(destination)], log_path)
            self._run(
                ["git", "-C", str(destination), "remote", "add", "origin", url],
                log_path,
            )
        remote = self._capture(
            ["git", "-C", str(destination), "remote", "get-url", "origin"]
        ).removesuffix(".git")
        if remote != url.removesuffix(".git"):
            raise PipelineError(f"tool remote mismatch for {name}")
        actual = self._capture_optional(
            ["git", "-C", str(destination), "rev-parse", "HEAD"]
        )
        if actual.casefold() != commit.casefold():
            self._run(
                [
                    "git",
                    "-C",
                    str(destination),
                    "fetch",
                    "--depth",
                    "1",
                    "--filter=blob:none",
                    "origin",
                    commit,
                ],
                log_path,
                timeout=int(self.pipeline["setup_timeout_seconds"]),
            )
            self._run(
                ["git", "-C", str(destination), "checkout", "--detach", "FETCH_HEAD"],
                log_path,
            )
            actual = self._capture(
                ["git", "-C", str(destination), "rev-parse", "HEAD"]
            )
        if actual.casefold() != commit.casefold():
            raise PipelineError(f"tool checkout mismatch for {name}")
        return {"name": name, "url": url, "commit": actual}

    def _prepare_integration(self, job_dir: Path, job: dict[str, Any]) -> None:
        route = str((job.get("route") or {}).get("name") or "")
        if route not in {"oss_fuzz_existing", "oss_fuzz_gen"}:
            raise PipelineError(f"integration route is not implemented: {route}")
        oss_fuzz = self.tools_root / "oss-fuzz"
        if not (oss_fuzz / ".git").is_dir():
            raise PipelineError("pinned OSS-Fuzz checkout is missing")
        repository_url = str((job.get("source") or {}).get("repository_url") or "")
        project_name, project_dir = self._find_oss_fuzz_project(
            oss_fuzz, repository_url
        )
        if route == "oss_fuzz_gen" and project_dir is None:
            raise PipelineError(
                "new OSS-Fuzz project generation is not implemented yet"
            )
        if project_dir is None:
            raise PipelineError("repository has no matching OSS-Fuzz integration")

        integration_dir = job_dir / "integration" / "oss-fuzz"
        integration_dir.mkdir(parents=True, exist_ok=True)
        hashes: dict[str, str] = {}
        for name in ("Dockerfile", "build.sh", "project.yaml"):
            source_path = project_dir / name
            if not source_path.is_file():
                raise PipelineError(f"OSS-Fuzz project is missing {name}")
            destination = integration_dir / name
            shutil.copy2(source_path, destination)
            hashes[name] = hashlib.sha256(destination.read_bytes()).hexdigest()

        source_checkout = job_dir / "source"
        build_source = job_dir / "build-source"
        commit = str((job.get("source") or {}).get("commit") or "")
        if build_source.exists():
            actual = self._capture(
                ["git", "-C", str(build_source), "rev-parse", "HEAD"]
            )
            if actual.casefold() != commit.casefold():
                raise PipelineError("existing build worktree is at the wrong commit")
        else:
            self._run(
                [
                    "git",
                    "-C",
                    str(source_checkout),
                    "worktree",
                    "add",
                    "--detach",
                    str(build_source),
                    commit,
                ],
                job_dir / "logs" / "integration.log",
            )
        self._write_json(
            job_dir / "artifacts" / "integration-manifest.json",
            {
                "schema_version": 1,
                "created_at": utc_now(),
                "route": route,
                "oss_fuzz_project": project_name,
                "oss_fuzz_commit": self._capture(
                    ["git", "-C", str(oss_fuzz), "rev-parse", "HEAD"]
                ),
                "target_commit": commit,
                "source_checkout": str(source_checkout),
                "build_worktree": str(build_source),
                "integration_file_sha256": hashes,
            },
        )

    def _build_fuzzers(self, job_dir: Path, job: dict[str, Any]) -> None:
        del job
        manifest = self._read_json(
            job_dir / "artifacts" / "integration-manifest.json"
        )
        project = str(manifest["oss_fuzz_project"])
        build_source = Path(manifest["build_worktree"])
        oss_fuzz = self.tools_root / "oss-fuzz"
        helper = oss_fuzz / "infra" / "helper.py"
        log_path = job_dir / "logs" / "oss-fuzz-build.log"
        timeout = int(self.pipeline["setup_timeout_seconds"])
        self._run_streaming(
            [
                "python3",
                str(helper),
                "build_image",
                "--no-pull",
                "--cache",
                project,
            ],
            log_path,
            timeout=timeout,
        )
        self._run_streaming(
            [
                "python3",
                str(helper),
                "build_fuzzers",
                "--clean",
                "--sanitizer",
                "address",
                project,
                str(build_source),
            ],
            log_path,
            timeout=timeout,
        )
        out_dir = oss_fuzz / "build" / "out" / project
        fuzzers = sorted(
            path.name
            for path in out_dir.iterdir()
            if path.is_file()
            and os.access(path, os.X_OK)
            and path.name != "llvm-symbolizer"
            and not path.name.endswith((".zip", ".dict", ".options"))
        )
        if not fuzzers:
            raise PipelineError("OSS-Fuzz build produced no executable fuzz targets")
        snapshot_root = job_dir / "build-output"
        snapshot_root.mkdir(exist_ok=True)
        snapshot = snapshot_root / "asan"
        temporary_snapshot = snapshot_root / f"asan.tmp-{time.time_ns()}"
        shutil.copytree(out_dir, temporary_snapshot)
        if snapshot.exists():
            shutil.rmtree(snapshot)
        temporary_snapshot.replace(snapshot)
        image_id = self._capture(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                f"gcr.io/oss-fuzz/{project}",
            ]
        )
        original_status = self._capture(
            ["git", "-C", str(job_dir / "source"), "status", "--porcelain"]
        )
        if original_status:
            raise PipelineError("evidence source checkout was modified during build")
        self._write_json(
            job_dir / "artifacts" / "build-manifest.json",
            {
                "schema_version": 1,
                "built_at": utc_now(),
                "engine": "libfuzzer",
                "sanitizer": "address",
                "oss_fuzz_project": project,
                "builder_image_id": image_id,
                "fuzz_targets": fuzzers,
                "output_directory": str(snapshot),
                "oss_fuzz_shared_output_directory": str(out_dir),
            },
        )

    def _fuzz_session(
        self,
        job_dir: Path,
        job: dict[str, Any],
        *,
        seconds: int,
        workers: int,
        label: str,
    ) -> dict[str, Any]:
        if seconds < 1 or workers < 1:
            raise PipelineError("fuzz duration and worker count must be positive")
        build = self._read_json(job_dir / "artifacts" / "build-manifest.json")
        smoke = self._read_json(job_dir / "artifacts" / "smoke.json")
        project = str(build["oss_fuzz_project"])
        fuzzer = self._session_target(job_dir, smoke, label)
        if fuzzer not in build.get("fuzz_targets", []):
            raise PipelineError("smoke target is not present in the build manifest")
        out_dir = Path(str(build["output_directory"]))
        if not out_dir.is_dir():
            raise PipelineError("job ASan build snapshot is missing")
        runtime_out = job_dir / "runtime-out" / label
        if not runtime_out.exists():
            runtime_out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(out_dir, runtime_out)
        corpus_dir = job_dir / "corpus" / fuzzer
        crash_dir = job_dir / "crashes" / fuzzer
        corpus_dir.mkdir(parents=True, exist_ok=True)
        crash_dir.mkdir(parents=True, exist_ok=True)
        self._seed_corpus(out_dir, fuzzer, corpus_dir)

        memory_mb = int(self.pipeline["container_memory_mb"])
        rss_limit_mb = int(self.pipeline["fuzzer_rss_limit_mb"])
        input_timeout = int(self.pipeline["input_timeout_seconds"])
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,exec,nosuid,size=1g",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "512",
            "--cpus",
            str(workers),
            "--memory",
            f"{memory_mb}m",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-e",
            "FUZZING_ENGINE=libfuzzer",
            "-e",
            "SANITIZER=address",
            "-e",
            "RUN_FUZZER_MODE=interactive",
            "-e",
            "HELPER=True",
            "-v",
            f"{runtime_out}:/out:rw",
            "-v",
            f"{corpus_dir}:/tmp/{fuzzer}_corpus:rw",
            "-v",
            f"{crash_dir}:/crashes:rw",
            "gcr.io/oss-fuzz-base/base-runner",
            "run_fuzzer",
            fuzzer,
            f"-max_total_time={seconds}",
            f"-timeout={input_timeout}",
            f"-rss_limit_mb={rss_limit_mb}",
            f"-artifact_prefix=/crashes/{fuzzer}-",
            "-print_final_stats=1",
            f"-jobs={workers}",
            f"-workers={workers}",
            "-ignore_crashes=1",
            "-ignore_timeouts=1",
            "-ignore_ooms=1",
        ]
        started_at = utc_now()
        monotonic_start = time.monotonic()
        log_path = job_dir / "logs" / f"{label}-{fuzzer}.log"
        self._run_streaming(command, log_path, timeout=seconds + 600)
        elapsed = round(time.monotonic() - monotonic_start, 3)
        crashes = sorted(path.name for path in crash_dir.iterdir() if path.is_file())
        corpus_files = sum(1 for path in corpus_dir.iterdir() if path.is_file())
        worker_stats = self._collect_worker_stats(runtime_out, job_dir / "logs", label)
        result = {
            "schema_version": 1,
            "label": label,
            "started_at": started_at,
            "completed_at": utc_now(),
            "elapsed_seconds": elapsed,
            "requested_seconds": seconds,
            "workers": workers,
            "project": project,
            "fuzz_target": fuzzer,
            "engine": "libfuzzer",
            "sanitizer": "address",
            "network": "none",
            "corpus_files": corpus_files,
            "crash_files": crashes,
            "worker_stats": worker_stats,
            "executed_units": sum(
                item.get("number_of_executed_units", 0) for item in worker_stats
            ),
            "log_path": str(log_path),
            "runtime_output_directory": str(runtime_out),
        }
        self._write_json(job_dir / "artifacts" / f"{label}-run.json", result)
        return result

    def _session_target(
        self, job_dir: Path, smoke: dict[str, Any], label: str
    ) -> str:
        if label != "fuzz":
            return str(smoke["fuzz_target"])
        plan = self._read_json(job_dir / "artifacts" / "coverage-plan.json")
        return str((plan.get("review") or {}).get("selected_fuzz_target") or "")

    @staticmethod
    def _seed_corpus(out_dir: Path, fuzzer: str, corpus_dir: Path) -> None:
        if any(corpus_dir.iterdir()):
            return
        archive = out_dir / f"{fuzzer}_seed_corpus.zip"
        if not archive.is_file():
            return
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                name = Path(member.filename)
                if member.is_dir() or name.is_absolute() or ".." in name.parts:
                    continue
                content = bundle.read(member)
                destination = corpus_dir / hashlib.sha256(content).hexdigest()
                destination.write_bytes(content)

    @staticmethod
    def _collect_worker_stats(
        runtime_out: Path, logs_dir: Path, label: str
    ) -> list[dict[str, int | str]]:
        records: list[dict[str, int | str]] = []
        pattern = re.compile(r"^stat::([a-z_]+):\s+(\d+)", re.MULTILINE)
        for index, source in enumerate(sorted(runtime_out.rglob("fuzz-*.log"))):
            text = source.read_text(encoding="utf-8", errors="replace")
            destination = logs_dir / f"{label}-worker-{index}.log"
            shutil.copy2(source, destination)
            record: dict[str, int | str] = {"log_path": str(destination)}
            for name, value in pattern.findall(text):
                record[name] = int(value)
            records.append(record)
        return records

    def _smoke_fuzzer(self, job_dir: Path, job: dict[str, Any]) -> None:
        del job
        manifest = self._read_json(job_dir / "artifacts" / "build-manifest.json")
        fuzzers = [str(value) for value in manifest.get("fuzz_targets") or []]
        if not fuzzers:
            raise PipelineError("build manifest has no fuzz targets")
        preferred = str(manifest.get("generated_fuzz_target") or "")
        selected = preferred if preferred in fuzzers else _select_smoke_target(fuzzers)
        project = str(manifest["oss_fuzz_project"])
        helper = self.tools_root / "oss-fuzz" / "infra" / "helper.py"
        self._run(
            [
                "python3",
                str(helper),
                "check_build",
                "--sanitizer",
                "address",
                project,
                selected,
            ],
            job_dir / "logs" / "oss-fuzz-smoke.log",
            timeout=int(self.pipeline["smoke_seconds"]) + 180,
        )
        self._write_json(
            job_dir / "artifacts" / "smoke.json",
            {
                "schema_version": 1,
                "checked_at": utc_now(),
                "fuzz_target": selected,
                "sanitizer": "address",
                "status": "passed",
            },
        )

    @staticmethod
    def _archive_pre_generation_results(job_dir: Path, fuzz_target: str) -> None:
        stamp = str(time.time_ns())
        history = job_dir / "artifacts" / "history" / f"generation-{stamp}"
        history.mkdir(parents=True)
        for name in ("smoke.json", "probe-run.json", "quartet-review.json", "coverage-plan.json"):
            path = job_dir / "artifacts" / name
            if path.is_file():
                shutil.move(str(path), history / name)
        runtime_probe = job_dir / "runtime-out" / "probe"
        if runtime_probe.exists():
            runtime_probe.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(runtime_probe), runtime_probe.parent / f"probe-{stamp}")
        for category in ("corpus", "crashes"):
            root = job_dir / category
            selected = root / fuzz_target
            if selected.exists():
                destination = job_dir / f"{category}-history" / stamp / fuzz_target
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(selected), destination)

    @staticmethod
    def _find_oss_fuzz_project(
        oss_fuzz: Path, repository_url: str
    ) -> tuple[str, Path | None]:
        expected = repository_url.casefold().rstrip("/").removesuffix(".git")
        for project_yaml in sorted((oss_fuzz / "projects").glob("*/project.yaml")):
            text = project_yaml.read_text(encoding="utf-8", errors="replace")
            match = re.search(
                r"(?m)^main_repo:\s*['\"]?([^'\"\s]+)", text
            )
            if not match:
                continue
            current = match.group(1).casefold().rstrip("/").removesuffix(".git")
            if current == expected:
                return project_yaml.parent.name, project_yaml.parent
        return "", None

    def _job_dir(self, job_id: str) -> Path:
        if not JOB_ID_PATTERN.fullmatch(job_id):
            raise PipelineError(f"invalid job id: {job_id}")
        root = self.runs_root.resolve()
        candidate = self.runs_root / job_id
        if candidate.is_symlink() or not candidate.is_dir():
            raise PipelineError(f"job directory was not found: {candidate}")
        resolved = candidate.resolve()
        if resolved.parent != root:
            raise PipelineError("job directory escaped the configured runs root")
        return resolved

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PipelineError(f"could not read {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise PipelineError(f"expected an object in {path}")
        return value

    @staticmethod
    def _write_json(path: Path, value: dict[str, Any]) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)

    @staticmethod
    def _capture(command: list[str]) -> str:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=_subprocess_environment(),
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-1000:]
            raise PipelineError(f"command failed: {command[0]}: {detail}")
        return result.stdout.strip()

    @staticmethod
    def _capture_optional(command: list[str]) -> str:
        try:
            return PipelineRunner._capture(command)
        except PipelineError:
            return ""

    @staticmethod
    def _run(
        command: list[str], log_path: Path, timeout: int = 300
    ) -> None:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=_subprocess_environment(),
            timeout=timeout,
            check=False,
        )
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {' '.join(command[:4])}\n")
            handle.write(result.stdout)
            handle.write(result.stderr)
            handle.write(f"\nexit={result.returncode}\n")
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-2000:]
            raise PipelineError(f"command failed: {command[0]}: {detail}")

    @staticmethod
    def _run_streaming(command: list[str], log_path: Path, timeout: int) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {' '.join(command[:6])}\n")
            handle.flush()
            try:
                process = subprocess.Popen(
                    command,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    env=_subprocess_environment(),
                )
                return_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                raise PipelineError(f"command exceeded {timeout}s timeout") from exc
            handle.write(f"\nexit={return_code}\n")
        if return_code != 0:
            raise PipelineError(
                f"command failed with exit {return_code}; see {log_path}"
            )


def _subprocess_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "CODEX_API_KEY"):
        environment.pop(name, None)
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return environment


def _select_smoke_target(fuzzers: list[str]) -> str:
    priorities = ("parser", "parse", "packet", "decode", "read", "load")
    return min(
        fuzzers,
        key=lambda name: (
            next(
                (index for index, marker in enumerate(priorities) if marker in name.casefold()),
                len(priorities),
            ),
            len(name),
            name,
        ),
    )
