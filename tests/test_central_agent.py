from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fuzz_target_scout.central_agent import (
    CentralAgent,
    CentralCodex,
    TelegramNotifier,
    _failure_fingerprint,
    _followup_available,
    _health_incident_key,
    _health_job_view,
)
from fuzz_target_scout.config import load_config
from fuzz_target_scout.pipeline import PipelineError
from fuzz_target_scout.pipeline_worker import PipelineWorker, WorkerResult
from fuzz_target_scout.resources import ResourceAllocation, ResourceSnapshot


class CentralAgentTests(unittest.TestCase):
    def test_cycle_review_failure_continues_without_ai_improvement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            agent = CentralAgent(config)
            job_id = "org-target-aaaaaaaaaaaa"
            completed_id = "org-complete-bbbbbbbbbbbb"
            agent._cycle_job_evidence = lambda current: {"job_id": current}
            results = [
                WorkerResult(job_id, "interrupted", "fuzzing", "fuzz"),
                WorkerResult(completed_id, "exhausted", "complete", "fuzz"),
            ]
            allocation = ResourceAllocation(
                1, 1, 1920, 768, 1, 1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )

            with patch.object(
                agent.reviewer, "cycle", side_effect=PipelineError("review refused")
            ) as cycle, patch.object(agent, "_notify") as notify:
                review = agent._review_cycle(results, allocation)

            cycle.assert_called_once()
            notify.assert_called_once()
            self.assertEqual(notify.call_args.args[0], "cycle_review_unavailable")
            self.assertEqual(review["campaign_action"], "continue")
            self.assertEqual(review["resource_profile"], "conservative")
            self.assertEqual(
                {item["job_id"]: item["outcome"] for item in review["jobs"]},
                {job_id: "failed", completed_id: "limited"},
            )
            self.assertTrue(all(
                item["improvement"] == "manual_review" for item in review["jobs"]
            ))
            self.assertEqual(agent._apply_cycle_improvements(review, results), [])
            self.assertTrue(agent.state["cycle_review_unavailable"])
            record = json.loads(next((root / "agent" / "decisions").glob("*.json")).read_text())
            self.assertEqual(record["review_error"], "review_failed")
            self.assertNotIn("review refused", json.dumps(record))

    def test_cycle_review_retries_on_next_batch_and_preserves_explicit_pause(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            agent = CentralAgent(config)
            job_id = "org-target-aaaaaaaaaaaa"
            agent._cycle_job_evidence = lambda _job_id: {"job_id": job_id}
            result = WorkerResult(job_id, "exhausted", "complete", "fuzz")
            allocation = ResourceAllocation(
                1, 1, 1920, 768, 1, 1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            explicit_pause = {
                "summary": "Systemic evidence problem",
                "campaign_action": "pause",
                "resource_profile": "conservative",
                "jobs": [],
            }

            with patch.object(
                agent.reviewer, "cycle",
                side_effect=[PipelineError("review unavailable"), (explicit_pause, {})],
            ) as cycle, patch.object(agent, "_notify") as notify:
                first = agent._review_cycle([result], allocation)
                second = agent._review_cycle([result], allocation)

            self.assertEqual(first["campaign_action"], "continue")
            self.assertEqual(second["campaign_action"], "pause")
            self.assertEqual(cycle.call_count, 2)
            self.assertEqual(
                [call.args[0] for call in notify.call_args_list],
                ["cycle_review_unavailable", "cycle_review_recovered"],
            )
            self.assertNotIn("cycle_review_unavailable", agent.state)

    def test_cycle_review_alerts_again_after_recovery_and_recurrence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            agent = CentralAgent(config)
            agent._cycle_job_evidence = lambda current: {"job_id": current}
            result = WorkerResult("org-target-aaaaaaaaaaaa", "exhausted", "complete", "fuzz")
            allocation = ResourceAllocation(
                1, 1, 1920, 768, 1, 1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            valid_review = {
                "summary": "review complete",
                "campaign_action": "continue",
                "resource_profile": "balanced",
                "jobs": [],
            }
            responses = [
                PipelineError("first refusal"),
                PipelineError("same incident"),
                (valid_review, {}),
                PipelineError("new incident"),
                (valid_review, {}),
            ]

            with patch.object(agent.reviewer, "cycle", side_effect=responses), patch.object(
                agent.notifier, "send", return_value=(True, "sent")
            ) as send:
                for _ in responses:
                    agent._review_cycle([result], allocation)

            self.assertEqual(send.call_count, 4)
            records = [
                json.loads(line)
                for line in (root / "agent" / "notifications.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                [record["key"] for record in records],
                [
                    "cycle_review_unavailable",
                    "cycle_review_recovered",
                    "cycle_review_unavailable",
                    "cycle_review_recovered",
                ],
            )

    def test_restart_clears_old_pause_reason_but_new_pause_is_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            agent = CentralAgent(config)
            agent.state["paused_reason"] = "old pause"
            agent.monitor = lambda _reason: {}

            agent.run(once=True, discovery=False)
            self.assertNotIn("paused_reason", agent.state)

            allocation = ResourceAllocation(
                1, 1, 1920, 768, 1, 1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            agent._runnable_jobs = lambda: [{"job_id": "org-target-aaaaaaaaaaaa"}]
            agent._choose_capacity = lambda _count: (allocation, {})
            agent._run_monitored_batch = lambda _worker, _jobs, _capacity: [
                WorkerResult("org-target-aaaaaaaaaaaa", "exhausted", "complete", "fuzz")
            ]
            agent._review_cycle = lambda _results, _allocation: {
                "campaign_action": "pause",
                "summary": "new pause",
                "jobs": [],
            }
            agent._apply_cycle_improvements = lambda _review, _results: []

            class FakeWorker:
                _non_fuzz_lock = None

            with patch(
                "fuzz_target_scout.central_agent.PipelineWorker",
                return_value=FakeWorker(),
            ), patch.object(agent, "_notify"):
                result = agent.run(max_batches=1, discovery=False)

            self.assertEqual(result["status"], "paused")
            self.assertEqual(agent.state["paused_reason"], "new pause")

    def test_cycle_evidence_explains_low_yield_early_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            job_id = "google-benchmark-aaaaaaaaaaaa"
            artifacts = root / "runs" / job_id / "artifacts"
            artifacts.mkdir(parents=True)
            (artifacts.parent / "job.json").write_text(
                json.dumps({
                    "source": {"repository": "google/benchmark"},
                    "budgets": {"fuzz_seconds": 86400},
                }),
                encoding="utf-8",
            )
            (artifacts.parent / "state.json").write_text(
                json.dumps({
                    "status": "exhausted",
                    "stage": "complete",
                    "campaign_stop_reason": "low_yield",
                    "campaign_yield_reason": "shallow_reach",
                }),
                encoding="utf-8",
            )
            (artifacts / "fuzz-progress.json").write_text(
                json.dumps({
                    "completed_seconds": 7200,
                    "sessions": [{"accounted_seconds": 7200, "coverage_edges": 6}],
                }),
                encoding="utf-8",
            )
            (artifacts / "fuzz-run.json").write_text(
                json.dumps({"worker_stats": [{"coverage_edges": 6}]}),
                encoding="utf-8",
            )
            metrics = {
                "completed_seconds": 7200,
                "baseline_edges": 6,
                "best_edges": 6,
                "edge_growth": 0,
                "baseline_features": 8,
                "best_features": 8,
                "feature_growth": 0,
                "trailing_stagnation_seconds": 7200,
            }
            (artifacts / "campaign-yield.json").write_text(
                json.dumps({
                    "decision": "rotate_target",
                    "reason": "shallow_reach",
                    "metrics": {**metrics, "private_note": "do-not-send"},
                    "private_note": "do-not-send",
                }),
                encoding="utf-8",
            )

            evidence = CentralAgent(config)._cycle_job_evidence(job_id)

        self.assertEqual(evidence["status"], "exhausted")
        self.assertEqual(evidence["fuzz_budget_seconds"], 86400)
        self.assertEqual(evidence["fuzz_completed_seconds"], 7200)
        self.assertEqual(evidence["coverage_edges"], 6)
        self.assertEqual(evidence["campaign_stop_reason"], "low_yield")
        self.assertEqual(evidence["campaign_yield_reason"], "shallow_reach")
        self.assertEqual(evidence["campaign_yield"], {
            "decision": "rotate_target",
            "metrics": metrics,
        })
        self.assertNotIn("do-not-send", json.dumps(evidence))

    def test_runnable_jobs_quarantines_duplicate_queued_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            runs = Path(config["pipeline"]["runs_path"])
            runs.mkdir(parents=True)
            for name, status, stage in (
                ("prior-job", "skipped_after_recovery", "complete"),
                ("queued-job", "queued", "policy_recheck"),
            ):
                job_dir = runs / name
                job_dir.mkdir()
                (job_dir / "job.json").write_text(
                    json.dumps({
                        "job_id": name,
                        "source": {"repository": "PowerDNS/pdns"},
                        "created_at": "2026-09-27T00:00:00+00:00",
                    }),
                    encoding="utf-8",
                )
                (job_dir / "state.json").write_text(
                    json.dumps({
                        "job_id": name,
                        "status": status,
                        "stage": stage,
                        "created_at": "2026-09-27T00:00:00+00:00",
                        "updated_at": "2026-09-27T00:00:00+00:00",
                    }),
                    encoding="utf-8",
                )

            agent = CentralAgent(config)
            self.assertEqual(agent._runnable_jobs(), [])
            state = json.loads((runs / "queued-job" / "state.json").read_text())
            self.assertEqual(state["status"], "skipped_previously_attempted")
            self.assertEqual(state["previous_repository_job"], "prior-job")

    def test_health_monitor_reuses_and_rotates_a_persistent_codex_session(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["agent"]["session_state_path"] = str(root / "sessions.json")
            config["agent"]["persistent_health_session"] = True
            config["agent"]["health_session_rotation_checks"] = 2
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "severity": "healthy",
                            "notify": False,
                            "summary": "정상",
                            "problems": [],
                        }
                    ),
                    encoding="utf-8",
                )
                events = []
                if len(commands) == 1:
                    events.append(
                        json.dumps(
                            {
                                "type": "thread.started",
                                "thread_id": "12345678-1234-1234-1234-123456789abc",
                            }
                        )
                    )
                events.append(json.dumps({"type": "turn.completed", "usage": {}}))
                return subprocess.CompletedProcess(
                    command, 0, stdout="\n".join(events), stderr=""
                )

            with patch(
                "fuzz_target_scout.central_agent.shutil.which",
                return_value="/usr/bin/codex",
            ), patch(
                "fuzz_target_scout.central_agent.subprocess.run",
                side_effect=fake_run,
            ):
                reviewer = CentralCodex(config)
                reviewer.health({"jobs": []})
                reviewer.health({"jobs": []})

        self.assertNotIn("resume", commands[0])
        self.assertIn("resume", commands[1])
        self.assertIn("12345678-1234-1234-1234-123456789abc", commands[1])

    def test_health_monitor_is_ephemeral_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["agent"]["session_state_path"] = str(root / "sessions.json")
            Path(config["agent"]["session_state_path"]).write_text(
                json.dumps({
                    "thread_id": "12345678-1234-1234-1234-123456789abc",
                    "checks": 1,
                })
            )
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text(json.dumps({
                    "severity": "healthy",
                    "notify": False,
                    "summary": "정상",
                    "problems": [],
                }))
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps({"type": "turn.completed", "usage": {}}),
                    stderr="",
                )

            with patch(
                "fuzz_target_scout.central_agent.shutil.which",
                return_value="/usr/bin/codex",
            ), patch(
                "fuzz_target_scout.central_agent.subprocess.run",
                side_effect=fake_run,
            ):
                CentralCodex(config).health({"jobs": []})

        self.assertIn("--ephemeral", commands[0])
        self.assertNotIn("resume", commands[0])
        self.assertFalse(Path(config["agent"]["session_state_path"]).exists())

    def test_codex_controller_uses_requested_model_and_hides_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            captured = {}

            def fake_run(command, **kwargs):
                captured["command"] = command
                captured["env"] = kwargs["env"]
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text(
                    json.dumps(
                        {
                            "parallel_jobs": 2,
                            "workers_per_job": 3,
                            "rationale": "안전한 처리량",
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(
                        {
                            "type": "turn.completed",
                            "usage": {"input_tokens": 10, "output_tokens": 4},
                        }
                    ),
                    stderr="",
                )

            environment = {
                "PATH": "/usr/bin",
                "GITHUB_TOKEN": "github-secret",
                "FUZZ_TELEGRAM_BOT_TOKEN": "telegram-secret",
                "FUZZ_TELEGRAM_CHAT_ID": "123456",
            }
            with patch.dict(
                "fuzz_target_scout.central_agent.os.environ",
                environment,
                clear=True,
            ), patch(
                "fuzz_target_scout.central_agent.shutil.which",
                return_value="/usr/bin/codex",
            ), patch(
                "fuzz_target_scout.central_agent.subprocess.run",
                side_effect=fake_run,
            ):
                decision, usage = CentralCodex(config).capacity({"safe_options": []})

        command = captured["command"]
        self.assertEqual(
            command[command.index("--model") + 1],
            "gpt-6-astra",
        )
        self.assertIn("model_reasoning_effort=high", command)
        self.assertNotIn("GITHUB_TOKEN", captured["env"])
        self.assertNotIn("FUZZ_TELEGRAM_BOT_TOKEN", captured["env"])
        self.assertEqual(decision["parallel_jobs"], 2)
        self.assertEqual(usage["output_tokens"], 4)

    def test_ai_capacity_is_clamped_to_deterministic_safe_options(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            agent = CentralAgent(config)
            agent.reviewer.capacity = lambda _evidence: (
                {
                    "parallel_jobs": 999,
                    "workers_per_job": 999,
                    "rationale": "too large",
                },
                {},
            )
            resource_snapshot = ResourceSnapshot(8, 8192, 6144, ("test",))

            def fake_plan(pipeline, requested_jobs=None, snapshot=None):
                del snapshot
                jobs = min(requested_jobs or 3, 3)
                configured_jobs = int(pipeline.get("max_parallel_jobs", 0))
                if configured_jobs > 0:
                    jobs = min(jobs, configured_jobs)
                safe_workers = {1: 6, 2: 3, 3: 2}[jobs]
                configured_workers = int(pipeline.get("parallel_workers", 0))
                workers = min(safe_workers, configured_workers or safe_workers)
                return ResourceAllocation(
                    jobs,
                    workers,
                    1024 + workers * 512,
                    512,
                    1,
                    1024,
                    resource_snapshot,
                )

            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                side_effect=fake_plan,
            ):
                allocation, _ = agent._choose_capacity(10)

        self.assertEqual(allocation.parallel_jobs, 3)
        self.assertEqual(allocation.workers_per_job, 2)

    def test_monitor_logs_progress_and_alerts_for_a_new_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            self._job(Path(config["pipeline"]["runs_path"]))
            agent = CentralAgent(config)
            agent.reviewer.health = lambda _evidence: (
                {
                    "severity": "healthy",
                    "notify": False,
                    "summary": "정상 진행 중",
                    "problems": [],
                },
                {},
            )
            messages = []
            agent.notifier.send = lambda message: (
                messages.append(message) or True,
                "ok",
            )
            allocation = ResourceAllocation(
                1,
                2,
                1920,
                768,
                1,
                1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                return_value=allocation,
            ):
                record = agent.monitor("scheduled_check")
                agent.monitor("scheduled_check")

            log_lines = Path(config["agent"]["log_path"]).read_text().splitlines()

        self.assertEqual(record["pending_finding_events"], 1)
        self.assertEqual(len(log_lines), 2)
        self.assertEqual(len(messages), 1)
        self.assertIn("crashes/fuzz/crash-1", messages[0])
        self.assertIn("검증 전", messages[0])
        self.assertIn("취약점 확정이 아닙니다", messages[0])

    def test_campaign_rotation_notification_is_sent_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            runs = root / "runs"
            job = runs / "org-parser-aaaaaaaaaaaa"
            (job / "artifacts").mkdir(parents=True)
            (job / "artifacts" / "campaign-yield.json").write_text(
                json.dumps(
                    {
                        "created_at": "2026-09-28T00:00:00+00:00",
                        "reason": "coverage_stagnation",
                        "metrics": {
                            "completed_seconds": 25200,
                            "baseline_edges": 800,
                            "best_edges": 900,
                            "trailing_stagnation_seconds": 21600,
                        },
                    }
                )
            )
            config["pipeline"]["runs_path"] = str(runs)
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            agent = CentralAgent(config)
            messages = []
            agent.notifier.send = lambda message: (
                messages.append(message) or True,
                "ok",
            )

            agent._notify_campaign_rotations()
            agent._notify_campaign_rotations()

        self.assertEqual(len(messages), 1)
        self.assertIn("커버리지 증가 정체", messages[0])
        self.assertIn("800 → 900", messages[0])

    def test_monitor_notifies_false_positive_triage_judgment_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            runs = root / "runs"
            config["pipeline"]["runs_path"] = str(runs)
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            job = runs / "org-parser-aaaaaaaaaaaa"
            artifacts = job / "artifacts"
            artifacts.mkdir(parents=True)
            (job / "job.json").write_text(json.dumps({"route": {"name": "test"}}))
            (job / "state.json").write_text(
                json.dumps(
                    {
                        "job_id": job.name,
                        "stage": "fuzzing",
                        "status": "running",
                        "updated_at": "2099-01-01T00:00:00Z",
                    }
                )
            )
            attempts = [
                {"returncode": 0, "signature": ""},
                {"returncode": 0, "signature": ""},
                {"returncode": 0, "signature": ""},
            ]
            (artifacts / "triage-summary.json").write_text(
                json.dumps(
                    {
                        "created_at": "2026-01-02T00:00:00Z",
                        "input_crash_count": 2,
                        "validated_group_count": 0,
                        "auto_resumable_false_positive": True,
                        "false_positive_reason": (
                            "mixed_runtime_artifacts_not_reproduced"
                        ),
                        "groups": [
                            {
                                "reproduced": False,
                                "representative": {
                                    "reproduction_attempts": attempts,
                                },
                            },
                            {
                                "reproduced": False,
                                "representative": {
                                    "reproduction_attempts": attempts,
                                },
                            },
                        ],
                    }
                )
            )
            agent = CentralAgent(config)
            agent.state["last_monitor_at"] = "2026-01-01T00:00:00Z"
            agent.reviewer.health = lambda _evidence: (
                {"severity": "healthy", "notify": False, "summary": "정상", "problems": []},
                {},
            )
            messages = []
            agent.notifier.send = lambda message: (messages.append(message) or True, "ok")
            allocation = ResourceAllocation(
                1, 2, 1920, 768, 1, 1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                return_value=allocation,
            ):
                first = agent.monitor("scheduled_check")
                second = agent.monitor("scheduled_check")

        self.assertEqual(first["pending_judgment_events"], 1)
        self.assertEqual(second["pending_judgment_events"], 0)
        self.assertEqual(len(messages), 1)
        self.assertIn("취약점 아님", messages[0])
        self.assertIn("재현: 0개 (입력당 3회 검증)", messages[0])
        self.assertIn("퍼징을 자동 재개", messages[0])

    def test_monitor_notifies_completed_validation_with_poc_and_impact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            runs = root / "runs"
            config["pipeline"]["runs_path"] = str(runs)
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            job = runs / "org-parser-aaaaaaaaaaaa"
            artifacts = job / "artifacts"
            artifacts.mkdir(parents=True)
            (job / "job.json").write_text(json.dumps({"route": {"name": "test"}}))
            (job / "state.json").write_text(
                json.dumps(
                    {
                        "job_id": job.name,
                        "stage": "complete",
                        "status": "ready_for_human",
                        "updated_at": "2099-01-01T00:00:00Z",
                    }
                )
            )
            (artifacts / "validation-agent-report.json").write_text(
                json.dumps(
                    {
                        "created_at": "2026-01-02T00:00:00Z",
                        "findings": [
                            {
                                "group_id": "0123456789abcdef",
                                "title": "Parser heap overflow",
                                "impact_assessment": "Parser out-of-bounds memory access.",
                                "confidence": "high",
                            }
                        ],
                        "poc_artifacts": [{"group_id": "0123456789abcdef"}],
                    }
                )
            )
            (artifacts / "bug-bounty-report-draft.md").write_text("report")
            agent = CentralAgent(config)
            agent.state["last_monitor_at"] = "2026-01-01T00:00:00Z"
            agent.reviewer.health = lambda _evidence: (
                {"severity": "healthy", "notify": False, "summary": "정상", "problems": []},
                {},
            )
            messages = []
            agent.notifier.send = lambda message: (messages.append(message) or True, "ok")
            allocation = ResourceAllocation(
                1, 2, 1920, 768, 1, 1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                return_value=allocation,
            ):
                record = agent.monitor("scheduled_check")

        self.assertEqual(record["pending_judgment_events"], 1)
        self.assertEqual(len(messages), 1)
        self.assertIn("AI 취약점 검증 완료", messages[0])
        self.assertIn("Parser heap overflow / 신뢰도 높음", messages[0])
        self.assertIn("Parser out-of-bounds memory access", messages[0])
        self.assertIn("로컬 PoC: 1개 생성", messages[0])
        self.assertIn("보고서 초안: 생성 완료", messages[0])

    def test_ai_incident_key_ignores_wording_changes_for_same_problem(self):
        first = {
            "severity": "warning",
            "summary": "커버리지 정체가 지속됩니다.",
            "problems": [{
                "job_id": "org-parser-aaaaaaaaaaaa",
                "reason": "커버리지 엣지가 533에 머뭅니다.",
                "recommended_action": "입력 전략을 점검하세요.",
            }],
        }
        second = {
            "severity": "warning",
            "summary": "퍼징 중 coverage 증가가 없습니다.",
            "problems": [{
                "job_id": "org-parser-aaaaaaaaaaaa",
                "reason": "coverage remains unchanged",
                "recommended_action": "review harness reachability",
            }],
        }
        different = {
            "severity": "warning",
            "summary": "빌드 실패",
            "problems": [{
                "job_id": "org-parser-aaaaaaaaaaaa",
                "reason": "build failed",
            }],
        }

        self.assertEqual(
            _health_incident_key([], first), _health_incident_key([], second)
        )
        self.assertNotEqual(
            _health_incident_key([], first), _health_incident_key([], different)
        )

    def test_monitor_suppresses_same_incident_and_notifies_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            agent = CentralAgent(config)
            messages = []
            agent.notifier.send = lambda message: (messages.append(message) or True, "ok")
            decisions = iter(
                [
                    {
                        "severity": "critical",
                        "notify": True,
                        "summary": "하네스 작업이 필요합니다.",
                        "problems": ["coverage blocked"],
                    },
                    {
                        "severity": "critical",
                        "notify": True,
                        "summary": "하네스 보완이 필요합니다.",
                        "problems": ["different AI wording is ignored"],
                    },
                    {
                        "severity": "healthy",
                        "notify": False,
                        "summary": "ARM64 퍼징이 정상 실행 중입니다.",
                        "problems": [],
                    },
                ]
            )
            agent.reviewer.health = lambda _evidence: (next(decisions), {})
            allocation = ResourceAllocation(
                1,
                3,
                2048,
                768,
                1,
                1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            blocked = {
                "job_count": 1,
                "status_counts": {"manual_review": 1},
                "total_disk_bytes": 0,
                "jobs": [
                    {
                        "job_id": "org-parser-aaaaaaaaaaaa",
                        "status": "manual_review",
                        "last_error": "coverage plan requires harness work",
                        "updated_at": "2026-01-01T00:00:00Z",
                    }
                ],
            }
            healthy = {
                "job_count": 1,
                "status_counts": {"running": 1},
                "total_disk_bytes": 0,
                "jobs": [
                    {
                        "job_id": "org-parser-aaaaaaaaaaaa",
                        "status": "running",
                        "last_error": None,
                        "updated_at": "2099-01-01T00:00:00Z",
                    }
                ],
            }
            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                return_value=allocation,
            ), patch(
                "fuzz_target_scout.central_agent.pipeline_overview",
                side_effect=[blocked, blocked, healthy],
            ):
                first = agent.monitor("scheduled_check")
                repeated = agent.monitor("scheduled_check")
                recovered = agent.monitor("scheduled_check")

        self.assertEqual(first["notification_transition"], "alerted")
        self.assertEqual(repeated["notification_transition"], "duplicate_suppressed")
        self.assertEqual(recovered["notification_transition"], "recovered")
        self.assertEqual(len(messages), 2)
        self.assertIn("중앙 상태 경고", messages[0])
        self.assertIn("중앙 상태 복구", messages[1])
        self.assertIn("실행 또는 준비 중인 작업: 1", messages[1])

    def test_empty_campaign_alerts_after_successful_discovery_and_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            config["agent"]["idle_discovery_interval_seconds"] = 3600
            allocation = ResourceAllocation(
                1, 2, 1920, 768, 1, 1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            empty = {
                "job_count": 0,
                "status_counts": {},
                "total_disk_bytes": 0,
                "jobs": [],
            }
            runnable = {
                **empty,
                "job_count": 1,
                "jobs": [{
                    "job_id": "org-parser-aaaaaaaaaaaa",
                    "status": "running",
                    "stage": "fuzzing",
                    "updated_at": "2099-01-01T00:00:00Z",
                }],
            }
            messages = []
            def configure(agent):
                agent.reviewer.health = lambda _evidence: (
                    {"severity": "healthy", "notify": False, "summary": "정상", "problems": []},
                    {},
                )
                agent.notifier.send = lambda message: (
                    messages.append(message) or True, "ok"
                )

            agent = CentralAgent(config)
            configure(agent)
            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                return_value=allocation,
            ), patch(
                "fuzz_target_scout.central_agent.pipeline_overview",
                side_effect=[empty, empty, empty, empty, runnable],
            ):
                before_discovery = agent.monitor("idle")
                self.assertNotIn("no_runnable_since", agent.state)
                agent.state["last_discovery"] = {"scan_id": 1, "discovered": 0}
                agent.reviewer.health = lambda _evidence: (
                    {"severity": "warning", "notify": True,
                     "summary": "실행 가능한 작업이 없음", "problems": []},
                    {},
                )
                warning = agent.monitor("idle")
                self.assertIn("no_runnable_since", agent.state)
                restarted = CentralAgent(config)
                configure(restarted)
                still_idle = restarted.monitor("idle")
                duplicate = restarted.monitor("idle")
                recovery = restarted.monitor("idle")

            self.assertEqual(before_discovery["notification_transition"], "unchanged")
            self.assertEqual(warning["notification_transition"], "alerted")
            self.assertEqual(still_idle["ai_decision"]["severity"], "healthy")
            self.assertEqual(still_idle["effective_severity"], "warning")
            self.assertEqual(still_idle["notification_transition"], "duplicate_suppressed")
            self.assertEqual(duplicate["notification_transition"], "duplicate_suppressed")
            self.assertEqual(recovery["notification_transition"], "recovered")
            self.assertEqual(len(messages), 2)
            self.assertIn("no_runnable_targets", messages[0])
            self.assertIn("실행 가능한 작업: 1", messages[1])
            self.assertNotIn("no_runnable_since", restarted.state)
            self.assertNotIn("no_runnable_since", CentralAgent(config).state)

    def test_empty_campaign_never_recovers_on_ai_notify_flip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            allocation = ResourceAllocation(
                1, 2, 1920, 768, 1, 1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            empty = {"job_count": 0, "status_counts": {},
                     "total_disk_bytes": 0, "jobs": []}
            messages = []
            agent = CentralAgent(config)
            agent.state["last_discovery"] = {"scan_id": 1}
            decisions = iter([
                {"severity": "warning", "notify": True,
                 "summary": "후보 없음", "problems": []},
                {"severity": "healthy", "notify": False,
                 "summary": "정상", "problems": []},
            ])
            agent.reviewer.health = lambda _evidence: (next(decisions), {})
            agent.notifier.send = lambda message: (
                messages.append(message) or True, "ok"
            )
            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                return_value=allocation,
            ), patch(
                "fuzz_target_scout.central_agent.pipeline_overview",
                return_value=empty,
            ), patch.object(
                agent, "_operational_problems", return_value=[]
            ):
                warning = agent.monitor("idle")
                still_idle = agent.monitor("idle")
            self.assertEqual(warning["notification_transition"], "alerted")
            self.assertEqual(still_idle["notification_transition"], "still_unavailable")
            self.assertEqual(len(messages), 1)
            self.assertIn("active_health_incident", agent.state)

    def test_health_evidence_treats_completed_failures_as_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            agent = CentralAgent(config)
            allocation = ResourceAllocation(
                1, 2, 1920, 768, 1, 1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            overview = {
                "job_count": 3,
                "status_counts": {"running": 1, "skipped_after_recovery": 2},
                "total_disk_bytes": 0,
                "jobs": [
                    {"job_id": "org-live-aaaaaaaaaaaa", "status": "running"},
                    {"job_id": "org-old-bbbbbbbbbbbb", "status": "skipped_after_recovery"},
                    {"job_id": "org-old-cccccccccccc", "status": "skipped_after_recovery"},
                ],
            }
            evidence = agent._health_evidence(overview, allocation, [], 0)

        self.assertEqual(evidence["status_counts"], {"running": 1})
        self.assertEqual(
            evidence["historical_outcomes"], {"skipped_after_recovery": 2}
        )
        self.assertEqual(
            [item["job_id"] for item in evidence["jobs"]],
            ["org-live-aaaaaaaaaaaa"],
        )

    def test_health_alert_cooldown_suppresses_ai_wording_churn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            agent = CentralAgent(config)
            messages = []
            agent.notifier.send = lambda message: (
                messages.append(message) or True,
                "ok",
            )
            decisions = iter([
                {"severity": "warning", "notify": True, "summary": "빌드 지연", "problems": ["build slow"]},
                {"severity": "warning", "notify": True, "summary": "커버리지 지연", "problems": ["coverage slow"]},
            ])
            agent.reviewer.health = lambda _evidence: (next(decisions), {})
            allocation = ResourceAllocation(
                1, 2, 1920, 768, 1, 1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            overview = {
                "job_count": 1,
                "status_counts": {"running": 1},
                "total_disk_bytes": 0,
                "jobs": [{
                    "job_id": "org-live-aaaaaaaaaaaa",
                    "status": "running",
                    "updated_at": "2099-01-01T00:00:00Z",
                }],
            }
            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                return_value=allocation,
            ), patch(
                "fuzz_target_scout.central_agent.pipeline_overview",
                return_value=overview,
            ):
                first = agent.monitor("scheduled_check")
                second = agent.monitor("scheduled_check")

        self.assertEqual(first["notification_transition"], "alerted")
        self.assertEqual(second["notification_transition"], "cooldown_suppressed")
        self.assertEqual(len(messages), 1)

    def test_monitor_queues_allowlisted_strategy_and_notifies_telegram(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            runs = root / "runs"
            config["pipeline"]["runs_path"] = str(runs)
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            job = runs / "org-parser-aaaaaaaaaaaa"
            artifacts = job / "artifacts"
            artifacts.mkdir(parents=True)
            (job / "state.json").write_text(
                json.dumps({"stage": "fuzzing", "status": "running"})
            )
            (job / "job.json").write_text(
                json.dumps({"route": {"name": "native_generated"}})
            )
            (artifacts / "fuzz-progress.json").write_text(
                json.dumps(
                    {
                        "coverage_stalled": True,
                        "stagnation_dictionary_applied": True,
                    }
                )
            )
            (artifacts / "coverage-plan.json").write_text(
                json.dumps({"evidence": {"execution_mode": "native_container"}})
            )
            overview = {
                "job_count": 1,
                "status_counts": {"running": 1},
                "total_disk_bytes": 0,
                "jobs": [
                    {
                        "job_id": job.name,
                        "status": "running",
                        "stage": "fuzzing",
                        "coverage_stalled": True,
                        "updated_at": "2099-01-01T00:00:00Z",
                    }
                ],
            }
            agent = CentralAgent(config)
            agent.reviewer.health = lambda _evidence: (
                {
                    "severity": "warning",
                    "notify": True,
                    "summary": "커버리지 정체 대응",
                    "problems": [],
                    "actions": [
                        {
                            "job_id": job.name,
                            "strategy": "enable_value_profile",
                            "rationale": "비교 피드백을 확대합니다.",
                        }
                    ],
                },
                {},
            )
            messages = []
            agent.notifier.send = lambda message: (
                messages.append(message) or True,
                "ok",
            )
            allocation = ResourceAllocation(
                1,
                2,
                1920,
                768,
                1,
                1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                return_value=allocation,
            ), patch(
                "fuzz_target_scout.central_agent.pipeline_overview",
                return_value=overview,
            ):
                record = agent.monitor("scheduled_check")

            adaptive = json.loads(
                (artifacts / "adaptive-strategy.json").read_text()
            )

        self.assertEqual(
            adaptive["history"][0]["strategy"], "enable_value_profile"
        )
        self.assertEqual(record["improvements"][0]["selection_source"], "ai")
        self.assertEqual(record["notification_transition"], "adaptive_handling")
        self.assertEqual(len(messages), 1)
        self.assertTrue(any("퍼징 전략을 변경" in message for message in messages))

    def test_monitor_recovers_failed_stage_and_notifies_action(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            runs = root / "runs"
            config["pipeline"]["runs_path"] = str(runs)
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            job = runs / "org-parser-aaaaaaaaaaaa"
            (job / "artifacts").mkdir(parents=True)
            (job / "job.json").write_text(
                json.dumps({"route": {"name": "native_generated"}})
            )
            (job / "state.json").write_text(
                json.dumps(
                    {
                        "job_id": job.name,
                        "stage": "build",
                        "status": "recovery_pending",
                        "last_error": "native build failed",
                        "attempts": {"worker_failures": 1},
                    }
                )
            )
            overview = {
                "job_count": 1,
                "status_counts": {"recovery_pending": 1},
                "total_disk_bytes": 0,
                "jobs": [
                    {
                        "job_id": job.name,
                        "stage": "build",
                        "status": "recovery_pending",
                        "last_error": "native build failed",
                        "updated_at": "2099-01-01T00:00:00Z",
                    }
                ],
            }
            captured = {}
            agent = CentralAgent(config)

            def decide(evidence):
                captured.update(evidence)
                return (
                    {
                        "severity": "warning",
                        "notify": True,
                        "summary": "빌드 단계를 한 번 재시도합니다.",
                        "problems": [
                            {
                                "job_id": job.name,
                                "reason": "native build failed",
                                "recommended_action": "retry",
                            }
                        ],
                        "actions": [],
                        "recovery_actions": [
                            {
                                "job_id": job.name,
                                "action": "retry_stage",
                                "rationale": "일시적인 빌드 실패인지 확인합니다.",
                            }
                        ],
                    },
                    {},
                )

            agent.reviewer.health = decide
            messages = []
            agent.notifier.send = lambda message: (
                messages.append(message) or True,
                "ok",
            )
            allocation = ResourceAllocation(
                1,
                2,
                1920,
                768,
                1,
                1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                return_value=allocation,
            ), patch(
                "fuzz_target_scout.central_agent.pipeline_overview",
                return_value=overview,
            ):
                record = agent.monitor("cycle_complete")

            state = json.loads((job / "state.json").read_text())
            recovery = json.loads(
                (job / "artifacts" / "central-recovery.json").read_text()
            )

        options = captured["jobs"][0]["failure_recovery"]["options"]
        self.assertEqual(options[0]["action"], "retry_stage")
        self.assertEqual(state["status"], "integrated")
        self.assertEqual(state["stage"], "build")
        self.assertEqual(state["attempts"]["worker_failures"], 0)
        self.assertEqual(recovery["history"][0]["selection_source"], "ai")
        self.assertEqual(record["notification_transition"], "unchanged")
        self.assertEqual(len(messages), 1)
        self.assertIn("중단된 퍼징 작업을 처리", messages[0])

    def test_restart_from_integration_selects_a_different_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            job = root / "runs" / "org-parser-aaaaaaaaaaaa"
            artifacts = job / "artifacts"
            artifacts.mkdir(parents=True)
            (job / "job.json").write_text(
                json.dumps({"route": {"name": "native_generated"}})
            )
            (job / "state.json").write_text(
                json.dumps(
                    {
                        "job_id": job.name,
                        "stage": "build",
                        "status": "recovery_pending",
                        "last_error": "repeated build failure",
                        "attempts": {"worker_failures": 1},
                    }
                )
            )
            (artifacts / "generic-integration.json").write_text(
                json.dumps(
                    {"candidate": {"file": "tests/fuzz/failed_fuzzer.c"}}
                )
            )
            (artifacts / "fuzz-progress.json").write_text(
                json.dumps({"completed_seconds": 1200})
            )
            agent = CentralAgent(config)
            result = agent._apply_failure_recovery(
                job.name,
                "restart_from_integration",
                "다른 하네스로 통합을 다시 생성합니다.",
                "ai",
            )
            final_state = json.loads((job / "state.json").read_text())
            exclusions = json.loads(
                (artifacts / "harness-exclusions.json").read_text()
            )
            progress_preserved = (artifacts / "fuzz-progress.json").is_file()
            integration_archived = not (
                artifacts / "generic-integration.json"
            ).exists()

        self.assertEqual(result["action"], "restart_from_integration")
        self.assertEqual(final_state["stage"], "integration")
        self.assertEqual(final_state["status"], "prepared")
        self.assertEqual(
            exclusions["paths"], ["tests/fuzz/failed_fuzzer.c"]
        )
        self.assertTrue(progress_preserved)
        self.assertTrue(integration_archived)

    def test_recovery_exhaustion_skips_target_instead_of_stalling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            job = root / "runs" / "org-parser-aaaaaaaaaaaa"
            artifacts = job / "artifacts"
            artifacts.mkdir(parents=True)
            (job / "job.json").write_text(
                json.dumps({"route": {"name": "native_generated"}})
            )
            state = {
                "job_id": job.name,
                "stage": "integration",
                "status": "recovery_pending",
                "last_error": "permanent integration failure",
                "attempts": {"worker_failures": 1},
            }
            (job / "state.json").write_text(json.dumps(state))
            agent = CentralAgent(config)
            fingerprint = _failure_fingerprint(
                "integration", state["last_error"]
            )
            (artifacts / "central-recovery.json").write_text(
                json.dumps(
                    {
                        "history": [
                            {
                                "status": "applied",
                                "action": "retry_stage",
                                "failure_fingerprint": fingerprint,
                            },
                            {
                                "status": "applied",
                                "action": "retry_stage",
                                "failure_fingerprint": fingerprint,
                            },
                        ]
                    }
                )
            )
            evidence = agent._failure_recovery_evidence(job.name, state)
            result = agent._apply_failure_recovery(
                job.name,
                "skip_target",
                "자동 복구 횟수를 모두 사용했습니다.",
                "deterministic_fallback",
            )
            final_state = json.loads((job / "state.json").read_text())

        self.assertEqual(
            [item["action"] for item in evidence["options"]], ["skip_target"]
        )
        self.assertEqual(result["action"], "skip_target")
        self.assertEqual(final_state["stage"], "complete")
        self.assertEqual(final_state["status"], "skipped_after_recovery")

    def test_bounded_quartet_exhaustion_only_allows_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            job = root / "runs" / "org-parser-aaaaaaaaaaaa"
            artifacts = job / "artifacts"
            artifacts.mkdir(parents=True)
            (job / "job.json").write_text(
                json.dumps({"route": {"name": "native_generated"}})
            )
            state = {
                "job_id": job.name,
                "stage": "quartet_gate",
                "status": "quartet_review_required",
                "bounded_exhaustion": "quartet_gate",
                "last_error": (
                    "Quartet quality gate exhausted its bounded target and repair attempts"
                ),
                "attempts": {"worker_failures": 1, "quartet_repair": 2},
            }
            (job / "state.json").write_text(json.dumps(state))
            agent = CentralAgent(config)

            evidence = agent._failure_recovery_evidence(job.name, state)
            result = agent._apply_failure_recovery(
                job.name,
                "skip_target",
                "The bounded quality repair budget is exhausted.",
                "deterministic_fallback",
            )
            final_state = json.loads((job / "state.json").read_text())

        self.assertTrue(evidence["eligible"])
        self.assertEqual(evidence["bounded_exhaustion"], "quartet_gate")
        self.assertEqual(
            [item["action"] for item in evidence["options"]], ["skip_target"]
        )
        self.assertEqual(result["action"], "skip_target")
        self.assertEqual(final_state["stage"], "complete")
        self.assertEqual(final_state["status"], "skipped_after_recovery")

    def test_dependency_failure_does_not_exclude_a_valid_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            job = root / "runs" / "org-parser-aaaaaaaaaaaa"
            artifacts = job / "artifacts"
            logs = job / "logs"
            artifacts.mkdir(parents=True)
            logs.mkdir()
            (job / "job.json").write_text(
                json.dumps({"route": {"name": "native_generated"}})
            )
            (job / "state.json").write_text(
                json.dumps(
                    {
                        "job_id": job.name,
                        "stage": "build",
                        "status": "recovery_pending",
                        "last_error": "command failed",
                        "attempts": {"worker_failures": 1},
                    }
                )
            )
            (artifacts / "generic-integration.json").write_text(
                json.dumps({"candidate": {"file": "tests/fuzz/fuzzer.cc"}})
            )
            (logs / "native-build.log").write_text(
                "Could not find abslConfig.cmake\n"
            )

            agent = CentralAgent(config)
            agent._apply_failure_recovery(
                job.name,
                "restart_from_integration",
                "의존성을 보완해 다시 통합합니다.",
                "ai",
            )

            self.assertFalse((artifacts / "harness-exclusions.json").exists())

    def test_graceful_fuzz_interruption_is_not_an_operational_failure(self):
        config, _ = load_config(Path("missing.toml"))
        agent = CentralAgent(config)
        for error in (
            "fuzzing stopped by operator",
            "command stopped by operator",
        ):
            item = {
                "job_id": "org-parser-aaaaaaaaaaaa",
                "status": "interrupted",
                "stage": "fuzzing",
                "last_error": error,
            }

            self.assertEqual(agent._operational_problems({"jobs": [item]}), [])
            health = _health_job_view(item)
            self.assertEqual(health["status"], "ready")
            self.assertIsNone(health["last_error"])
            self.assertIn("resumable", health["resume_note"])

    def test_cycle_review_and_improvement_finish_before_the_next_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            agent = CentralAgent(config)
            allocation = ResourceAllocation(
                1,
                2,
                1920,
                768,
                1,
                1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            order = []
            agent._runnable_jobs = lambda: [{"job_id": "job-1"}]
            agent._choose_capacity = lambda _count: (allocation, {})
            agent._run_monitored_batch = lambda _worker, _jobs, _capacity: (
                order.append("run")
                or [WorkerResult("job-1", "exhausted", "complete", "fuzz")]
            )
            agent._review_cycle = lambda _results, _allocation: (
                order.append("review")
                or {
                    "campaign_action": "continue",
                    "summary": "done",
                    "jobs": [],
                }
            )
            agent._apply_cycle_improvements = lambda _review, _results: (
                order.append("improve") or []
            )
            agent.monitor = lambda _reason: {}

            class FakeWorker:
                _non_fuzz_lock = None

            with patch(
                "fuzz_target_scout.central_agent.PipelineWorker",
                return_value=FakeWorker(),
            ):
                result = agent.run(
                    max_batches=2,
                    exit_when_idle=True,
                    discovery=False,
                )

        self.assertEqual(
            order, ["run", "review", "improve", "run", "review", "improve"]
        )
        self.assertEqual(result["completed_batches"], 2)

    def test_stop_only_sets_events_and_never_blocks_on_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            agent = CentralAgent(config)

            class FakeWorker:
                stopped = False

                def stop(self):
                    self.stopped = True

            worker = FakeWorker()
            agent._active_worker = worker
            with patch.object(agent, "_stop_active_containers") as cleanup:
                agent.stop()

        self.assertTrue(agent.stop_event.is_set())
        self.assertTrue(worker.stopped)
        cleanup.assert_not_called()

    def test_active_container_cleanup_is_batched_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            agent = CentralAgent(config)
            first = agent.runs_root / "first"
            second = agent.runs_root / "second"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            (first / "state.json").write_text(
                json.dumps({"active_fuzz_container": "fts-zeta-123"})
            )
            (second / "state.json").write_text(
                json.dumps(
                    {
                        "active_fuzz_container": "fts-alpha-123",
                        "active_afl_container": "invalid container",
                    }
                )
            )
            with patch("fuzz_target_scout.central_agent.subprocess.run") as run:
                agent._stop_active_containers()

        run.assert_called_once()
        self.assertEqual(
            run.call_args.args[0],
            ["docker", "rm", "-f", "fts-alpha-123", "fts-zeta-123"],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 20)

    def test_idle_wait_ends_at_next_discovery_due_time(self):
        agent = object.__new__(CentralAgent)
        agent.agent = {
            "auto_discover": True,
            "monitor_interval_seconds": 1800,
            "discovery_interval_seconds": 21600,
            "idle_discovery_interval_seconds": 3600,
            "discovery_error_retry_seconds": 300,
        }
        now = datetime(2026, 10, 2, 3, 50, tzinfo=timezone.utc)
        agent.state = {"last_discovery_at": "2026-10-02T03:00:00+00:00"}
        self.assertEqual(agent._idle_wait_seconds(discovery=True, now=now), 600)

        agent.state["last_discovery_at"] = "2026-10-02T03:47:00+00:00"
        agent.state["last_discovery_error"] = "temporary API failure"
        self.assertEqual(agent._idle_wait_seconds(discovery=True, now=now), 120)

        agent.state["last_discovery_at"] = "2026-10-02T02:00:00+00:00"
        self.assertEqual(agent._idle_wait_seconds(discovery=True, now=now), 1)
        agent.agent["auto_discover"] = False
        self.assertEqual(agent._idle_wait_seconds(discovery=True, now=now), 1800)
        agent.agent["auto_discover"] = True
        self.assertEqual(agent._idle_wait_seconds(discovery=False, now=now), 1800)

    def test_idle_discovery_uses_wider_search_than_active_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["idle_search_pages_per_query"] = 3
            agent = CentralAgent(config)
            calls = []
            exports = []
            backlog_requests = []

            class BacklogStore:
                def __init__(self, _path):
                    pass

                def revalidation_backlog_names(self, score, languages, excluded, limit):
                    backlog_requests.append((score, languages, excluded, limit))
                    return ["org/fresh"]

                def close(self):
                    pass

            class FakeEngine:
                def __init__(self, _config, progress):
                    pass

                def scan(self, **kwargs):
                    calls.append(kwargs)
                    return SimpleNamespace(
                        scan_id=len(calls), discovered=0, verified=0,
                        errors=2 if len(calls) == 1 else 0,
                        arm_preflight_attempted=0, arm_preflight_passed=0,
                    )

                def close(self):
                    pass

            agent._export_verified_candidates = (
                lambda scan_id, *, scan_errors: exports.append((scan_id, scan_errors))
            )
            agent._plan_exported_candidates = lambda: None
            agent._runnable_jobs = lambda: []
            with patch("fuzz_target_scout.central_agent.ScoutEngine", FakeEngine), patch(
                "fuzz_target_scout.central_agent.Store", BacklogStore
), patch(
                "fuzz_target_scout.central_agent.repository_discovery_exclusions",
                return_value={"org/old"},
            ):
                agent._refresh_candidates_if_due()
                agent.state["last_discovery_at"] = "2020-01-01T00:00:00Z"
                agent._runnable_jobs = lambda: [{"job_id": "ready-job"}]
                agent._refresh_candidates_if_due()

        self.assertEqual(
            [call["search_pages_per_query"] for call in calls], [3, 1]
        )
        self.assertEqual(exports, [(1, 2), (2, 0)])
        self.assertEqual([call["seed_repositories"] for call in calls],
                         [["org/fresh"], ["org/fresh"]])
        self.assertEqual(backlog_requests[0], (55, ["C", "C++"], {"org/old"}, 6))

    def test_partial_empty_scan_retains_only_a_usable_verified_export(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "verified-candidates.jsonl"
            previous = {
                "repository": "org/previous",
                "commit": "a" * 40,
                "language": "C++",
                "policy": {
                    "status": "verified",
                    "program_url": "https://example.test/bounty",
                    "security_url": "https://example.test/security",
                },
                "architecture": {"compatible": True},
                "assessment": {"final_score": 75},
            }
            original = json.dumps(previous) + "\n"
            output.write_text(original, encoding="utf-8")
            messages = []
            agent = SimpleNamespace(
                config={
                    "storage": {
                        "export_path": str(output),
                        "database_path": str(Path(directory) / "unused.sqlite3"),
                    },
                    "scoring": {"minimum_handoff_score": 55},
                    "architecture": {"mode": "native_only"},
                },
                pipeline={"languages": ["C++"]},
                progress=messages.append,
            )

            class EmptyStore:
                def __init__(self, _path):
                    pass

                def export_rows(self, *_args, **_kwargs):
                    return iter(())

                def close(self):
                    pass

            with patch("fuzz_target_scout.central_agent.Store", EmptyStore):
                preserved = CentralAgent._export_verified_candidates(
                    agent, 7, scan_errors=2
                )
                self.assertTrue(preserved)
                self.assertEqual(output.read_text(encoding="utf-8"), original)
                self.assertTrue(messages)

                replaced = CentralAgent._export_verified_candidates(
                    agent, 8, scan_errors=0
                )
                self.assertFalse(replaced)
                self.assertEqual(output.read_text(encoding="utf-8"), "")

                previous["policy"]["status"] = "conditional"
                output.write_text(json.dumps(previous) + "\n", encoding="utf-8")
                preserved = CentralAgent._export_verified_candidates(
                    agent, 9, scan_errors=1
                )
                self.assertFalse(preserved)
                self.assertEqual(output.read_text(encoding="utf-8"), "")

                previous["policy"]["status"] = "verified"
                output.write_text(
                    json.dumps(previous) + "\n" + '{"repository":"org/invalid"}\n',
                    encoding="utf-8",
                )
                preserved = CentralAgent._export_verified_candidates(
                    agent, 10, scan_errors=1
                )
                self.assertFalse(preserved)
                self.assertEqual(output.read_text(encoding="utf-8"), "")

    def test_partial_scan_with_new_eligible_candidate_replaces_old_export(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "verified-candidates.jsonl"
            output.write_text('{"repository":"org/old"}\n', encoding="utf-8")
            fresh = {
                "repository": "org/new",
                "policy": {"status": "verified"},
                "architecture": {"compatible": True},
            }
            agent = SimpleNamespace(
                config={
                    "storage": {
                        "export_path": str(output),
                        "database_path": str(Path(directory) / "unused.sqlite3"),
                    },
                    "scoring": {"minimum_handoff_score": 55},
                    "architecture": {"mode": "native_only"},
                },
                pipeline={"languages": ["C++"]},
                progress=lambda _message: None,
            )

            class FreshStore:
                def __init__(self, _path):
                    pass

                def export_rows(self, *_args, **_kwargs):
                    return iter((fresh,))

                def close(self):
                    pass

            with patch("fuzz_target_scout.central_agent.Store", FreshStore):
                preserved = CentralAgent._export_verified_candidates(
                    agent, 10, scan_errors=1
                )
            self.assertFalse(preserved)
            self.assertEqual(
                [json.loads(line) for line in output.read_text().splitlines()],
                [fresh],
            )

    def test_candidate_discovery_honors_stop_without_failure_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["pipeline"]["input_path"] = str(root / "candidates.jsonl")
            config["storage"]["database_path"] = str(root / "scout.sqlite3")
            config["storage"]["export_path"] = str(root / "candidates.jsonl")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            agent = CentralAgent(config)
            messages = []
            agent.notifier.send = lambda message: (
                messages.append(message) or True,
                "ok",
            )

            class FakeEngine:
                def __init__(self, _config, progress):
                    self.progress = progress

                def scan(self, **_kwargs):
                    agent.stop()
                    self.progress("discovery checkpoint")
                    raise AssertionError("stop-aware progress should interrupt")

                def close(self):
                    pass

            with patch(
                "fuzz_target_scout.central_agent.ScoutEngine", FakeEngine
            ):
                agent._refresh_candidates_if_due()

        self.assertIn("last_discovery_interrupted_at", agent.state)
        self.assertNotIn("last_discovery_error", agent.state)
        self.assertEqual(messages, [])

    def test_restart_resumes_runnable_job_before_refreshing_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            config["pipeline"]["runs_path"] = str(root / "runs")
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            agent = CentralAgent(config)
            agent.state["batch_count"] = 99
            allocation = ResourceAllocation(
                1,
                2,
                1920,
                768,
                1,
                1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )
            order = []
            agent._runnable_jobs = lambda: [{"job_id": "job-1"}]
            agent._refresh_candidates_if_due = lambda: order.append("discover")
            agent._choose_capacity = lambda _count: (allocation, {})
            agent._run_monitored_batch = lambda _worker, _jobs, _capacity: (
                order.append("run")
                or [WorkerResult("job-1", "exhausted", "complete", "fuzz")]
            )
            agent._review_cycle = lambda _results, _allocation: {
                "campaign_action": "continue",
                "summary": "done",
                "jobs": [],
            }
            agent._apply_cycle_improvements = lambda _review, _results: []
            agent.monitor = lambda _reason: {}

            class FakeWorker:
                _non_fuzz_lock = None

            with patch(
                "fuzz_target_scout.central_agent.PipelineWorker",
                return_value=FakeWorker(),
            ):
                result = agent.run(max_batches=1, discovery=True)

        self.assertEqual(order, ["run"])
        self.assertEqual(result["completed_batches"], 1)

    def test_followup_harness_requires_terminal_gap_and_available_budget(self):
        state = {
            "status": "exhausted",
            "stage": "complete",
            "attempts": {"harness_generation": 0, "central_improvement": 0},
        }
        plan = {"evidence": {"gap_candidates": [{"id": "gap-1"}]}}

        available, _ = _followup_available(state, plan, 1, 2)
        state["attempts"]["central_improvement"] = 1
        exhausted, _ = _followup_available(state, plan, 1, 2)

        self.assertTrue(available)
        self.assertFalse(exhausted)

    def test_followup_harness_is_gated_and_restores_terminal_state_after_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "config.toml")
            runs = root / "runs"
            config["pipeline"]["runs_path"] = str(runs)
            config["agent"]["state_path"] = str(root / "agent" / "state.json")
            config["agent"]["log_path"] = str(root / "agent" / "progress.jsonl")
            config["agent"]["notification_log_path"] = str(
                root / "agent" / "notifications.jsonl"
            )
            config["agent"]["decisions_path"] = str(root / "agent" / "decisions")
            job = runs / "org-parser-aaaaaaaaaaaa"
            (job / "artifacts").mkdir(parents=True)
            state_path = job / "state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "status": "exhausted",
                        "stage": "complete",
                        "attempts": {
                            "harness_generation": 0,
                            "central_improvement": 0,
                        },
                    }
                ),
                encoding="utf-8",
            )
            (job / "artifacts" / "coverage-plan.json").write_text(
                json.dumps(
                    {
                        "evidence": {"gap_candidates": [{"id": "gap-1"}]},
                        "review": {
                            "decision": "baseline_existing",
                            "execution_ready": True,
                        },
                    }
                ),
                encoding="utf-8",
            )
            allocation = ResourceAllocation(
                1,
                2,
                1920,
                768,
                1,
                1024,
                ResourceSnapshot(4, 4096, 3072, ("test",)),
            )

            def fake_advance(_worker, job_id, *, setup_only, allocation):
                self.assertEqual(job_id, job.name)
                self.assertTrue(setup_only)
                self.assertEqual(allocation.parallel_jobs, 1)
                state = json.loads(state_path.read_text())
                self.assertEqual(state["status"], "harness_work_pending")
                state["status"] = "ready"
                state["stage"] = "fuzzing"
                state_path.write_text(json.dumps(state), encoding="utf-8")
                return WorkerResult(job_id, "ready", "fuzzing", "ready")

            agent = CentralAgent(config)
            with patch(
                "fuzz_target_scout.central_agent.plan_resources",
                return_value=allocation,
            ), patch(
                "fuzz_target_scout.central_agent.PipelineRunner.recheck_policy",
                return_value={"status": "verified"},
            ), patch.object(PipelineWorker, "_advance", new=fake_advance):
                result = agent._run_followup_harness(
                    job.name,
                    {
                        "job_id": job.name,
                        "improvement": "generate_followup_harness",
                    },
                )
            final_state = json.loads(state_path.read_text())
            final_plan = json.loads(
                (job / "artifacts" / "coverage-plan.json").read_text()
            )

        self.assertEqual(result["final_state"]["status"], "exhausted")
        self.assertEqual(final_state["attempts"]["central_improvement"], 1)
        self.assertEqual(final_plan["review"]["decision"], "generate_new_harness")

    def test_telegram_uses_environment_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            response = io.BytesIO(b'{"ok":true}')
            with patch.dict(
                "fuzz_target_scout.central_agent.os.environ",
                {
                    "FUZZ_TELEGRAM_BOT_TOKEN": "123456:abcdefghijklmnopqrstuvwxyz_12345",
                    "FUZZ_TELEGRAM_CHAT_ID": "-123456",
                },
                clear=True,
            ), patch(
                "fuzz_target_scout.central_agent.urlopen",
                return_value=response,
            ):
                delivered, detail = TelegramNotifier(config).send("test")

        self.assertTrue(delivered)
        self.assertEqual(detail, "delivered")

    def test_telegram_retries_transient_network_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            config["agent"]["telegram_retry_backoff_seconds"] = 0
            response = io.BytesIO(b'{"ok":true}')
            with patch.dict(
                "fuzz_target_scout.central_agent.os.environ",
                {
                    "FUZZ_TELEGRAM_BOT_TOKEN": "123456:abcdefghijklmnopqrstuvwxyz_12345",
                    "FUZZ_TELEGRAM_CHAT_ID": "-123456",
                },
                clear=True,
            ), patch(
                "fuzz_target_scout.central_agent.urlopen",
                side_effect=[OSError("temporary"), response],
            ) as request:
                delivered, detail = TelegramNotifier(config).send("test")

        self.assertTrue(delivered)
        self.assertEqual(detail, "delivered")
        self.assertEqual(request.call_count, 2)

    def test_operational_logs_redact_environment_and_token_patterns(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _ = load_config(Path(directory) / "missing.toml")
            token = "ghp_abcdefghijklmnopqrstuvwxyz123456"
            telegram = "123456:abcdefghijklmnopqrstuvwxyz_12345"
            with patch.dict(
                "fuzz_target_scout.central_agent.os.environ",
                {"GITHUB_TOKEN": token},
                clear=True,
            ):
                redacted = CentralAgent(config)._sanitize(
                    {"error": f"failed with {token} and {telegram}"}
                )

        self.assertNotIn(token, redacted["error"])
        self.assertNotIn(telegram, redacted["error"])
        self.assertEqual(redacted["error"].count("[REDACTED]"), 2)

    @staticmethod
    def _job(runs: Path) -> None:
        job = runs / "org-parser-aaaaaaaaaaaa"
        (job / "artifacts").mkdir(parents=True)
        (job / "crashes" / "fuzz").mkdir(parents=True)
        (job / "poc").mkdir()
        (job / "job.json").write_text(
            json.dumps(
                {
                    "source": {"repository": "org/parser", "commit": "a" * 40},
                    "route": {"name": "oss_fuzz_existing"},
                    "budgets": {"fuzz_seconds": 86400},
                }
            ),
            encoding="utf-8",
        )
        (job / "state.json").write_text(
            json.dumps(
                {
                    "job_id": job.name,
                    "status": "ready",
                    "stage": "fuzzing",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        (job / "crashes" / "fuzz" / "crash-1").write_bytes(b"crash")


if __name__ == "__main__":
    unittest.main()
