from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.central_agent import (
    CentralAgent,
    CentralCodex,
    TelegramNotifier,
    _followup_available,
    _health_incident_key,
)
from fuzz_target_scout.config import load_config
from fuzz_target_scout.pipeline_worker import PipelineWorker, WorkerResult
from fuzz_target_scout.resources import ResourceAllocation, ResourceSnapshot


class CentralAgentTests(unittest.TestCase):
    def test_health_monitor_reuses_and_rotates_a_persistent_codex_session(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = load_config(root / "missing.toml")
            config["agent"]["session_state_path"] = str(root / "sessions.json")
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
            "gpt-daybreak-blue-latest",
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
