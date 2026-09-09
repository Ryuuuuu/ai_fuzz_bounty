import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.coverage_analysis import (
    analysis_record,
    build_coverage_evidence,
    deterministic_review,
    validate_review,
)
from fuzz_target_scout.pipeline import PipelineError, UnsupportedIntegrationError
from fuzz_target_scout.pipeline_runner import PipelineRunner, _select_smoke_target
from fuzz_target_scout.quartet_gate import (
    _numbered_source_excerpt,
    find_harness_source,
    validate_quartet_review,
)


class PipelineRunnerTests(unittest.TestCase):
    def test_unsupported_integration_is_recorded_as_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "a" * 12
            job_dir = root / job_id
            (job_dir / "artifacts").mkdir(parents=True)
            (job_dir / "job.json").write_text("{}")
            (job_dir / "state.json").write_text(
                json.dumps({"stage": "integration", "attempts": {}})
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root
            with self.assertRaises(UnsupportedIntegrationError):
                runner._single_stage(
                    job_id,
                    expected="integration",
                    next_stage="build",
                    next_status="integrated",
                    action=lambda *_: (_ for _ in ()).throw(
                        UnsupportedIntegrationError("no pinned definition")
                    ),
                )
            state = json.loads((job_dir / "state.json").read_text())
            self.assertEqual(state["status"], "unsupported_integration")

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_integration_uses_job_specific_oss_fuzz_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            oss_fuzz = tools / "oss-fuzz"
            project = oss_fuzz / "projects" / "sample"
            project.mkdir(parents=True)
            (oss_fuzz / "infra").mkdir()
            (oss_fuzz / "infra" / "helper.py").write_text("# helper\n")
            (project / "project.yaml").write_text(
                "main_repo: https://github.com/org/parser\n", encoding="utf-8"
            )
            (project / "Dockerfile").write_text("FROM scratch\n")
            (project / "build.sh").write_text("#!/bin/sh\n")
            (project / "fuzz_parser.cc").write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long);\n"
            )
            self._git_commit(oss_fuzz)

            job_dir = root / "job"
            source = job_dir / "source"
            source.mkdir(parents=True)
            (source / "parser.cc").write_text("int parse();\n")
            self._git_commit(source)
            commit = subprocess.check_output(
                ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
            ).strip()
            for name in ("artifacts", "logs", "integration"):
                (job_dir / name).mkdir(exist_ok=True)

            runner = object.__new__(PipelineRunner)
            runner.tools_root = tools
            runner.pipeline = {"setup_timeout_seconds": 60}
            runner._prepare_integration(
                job_dir,
                {
                    "route": {"name": "oss_fuzz_existing"},
                    "source": {
                        "repository_url": "https://github.com/org/parser.git",
                        "commit": commit,
                    },
                },
            )

            manifest = json.loads(
                (job_dir / "artifacts" / "integration-manifest.json").read_text()
            )
            self.assertEqual(manifest["oss_fuzz_project"], "sample")
            self.assertTrue(Path(manifest["oss_fuzz_worktree"]).is_dir())
            self.assertNotEqual(Path(manifest["oss_fuzz_worktree"]), oss_fuzz)
            self.assertIn("fuzz_parser.cc", manifest["integration_file_sha256"])
            self.assertTrue(
                (job_dir / "integration" / "oss-fuzz" / "fuzz_parser.cc").is_file()
            )

    @staticmethod
    def _git_commit(repository: Path) -> None:
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "config",
                "user.email",
                "test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repository), "config", "user.name", "Test"],
            check=True,
        )
        subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True
        )

    def test_prepare_advances_resumably_to_integration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "a" * 12
            job_dir = root / job_id
            job_dir.mkdir()
            for name in ("artifacts", "logs"):
                (job_dir / name).mkdir()
            (job_dir / "job.json").write_text(
                json.dumps({"job_id": job_id}), encoding="utf-8"
            )
            (job_dir / "state.json").write_text(
                json.dumps(
                    {
                        "job_id": job_id,
                        "status": "queued",
                        "stage": "policy_recheck",
                        "attempts": {},
                    }
                ),
                encoding="utf-8",
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root
            runner.progress = lambda _message: None
            calls = []

            with patch.object(
                runner, "_recheck_policy", side_effect=lambda *_: calls.append("policy")
            ):
                with patch.object(
                    runner, "_checkout_source", side_effect=lambda *_: calls.append("source")
                ):
                    with patch.object(
                        runner,
                        "_sync_required_tools",
                        side_effect=lambda *_: calls.append("tools"),
                    ):
                        state = runner.prepare(job_id)

            self.assertEqual(calls, ["policy", "source", "tools"])
            self.assertEqual(state["status"], "prepared")
            self.assertEqual(state["stage"], "integration")
            self.assertEqual(
                state["attempts"],
                {"policy_recheck": 1, "source_checkout": 1, "tool_sync": 1},
            )
            self.assertTrue((job_dir / "validation").is_dir())

    def test_job_id_cannot_escape_runs_root(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = object.__new__(PipelineRunner)
            runner.runs_root = Path(directory)
            with self.assertRaises(PipelineError):
                runner._job_dir("../outside")

    def test_submodule_urls_reject_local_and_ssh_transports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".gitmodules"
            path.write_text(
                '[submodule "safe"]\n\turl = https://github.com/org/safe.git\n'
                '[submodule "relative"]\n\turl = ../relative.git\n'
            )
            PipelineRunner._validate_submodule_urls(path)
            for unsafe in ("file:///tmp/repo", "git@github.com:org/repo.git"):
                path.write_text(f'[submodule "bad"]\n\turl = {unsafe}\n')
                with self.assertRaises(PipelineError):
                    PipelineRunner._validate_submodule_urls(path)

    def test_finds_exact_oss_fuzz_project_and_prefers_parser_smoke_target(self):
        with tempfile.TemporaryDirectory() as directory:
            oss_fuzz = Path(directory)
            project = oss_fuzz / "projects" / "sample"
            project.mkdir(parents=True)
            (project / "project.yaml").write_text(
                "main_repo: 'https://github.com/org/parser.git'\n",
                encoding="utf-8",
            )
            name, path = PipelineRunner._find_oss_fuzz_project(
                oss_fuzz, "https://github.com/org/parser"
            )
            self.assertEqual(name, "sample")
            self.assertEqual(path, project)
            self.assertEqual(
                _select_smoke_target(["fuzz_load", "fuzz_packet", "fuzz_parser"]),
                "fuzz_parser",
            )

    def test_finds_exact_non_fuzz_named_harness_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            harness = source / "spinquic.cpp"
            harness.write_text(
                'extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, '
                "unsigned long size) { return data && size; }\n",
                encoding="utf-8",
            )
            self.assertEqual(find_harness_source(source, "spinquic"), harness)

    def test_seed_corpus_is_content_addressed_and_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            corpus = root / "corpus"
            out.mkdir()
            corpus.mkdir()
            with zipfile.ZipFile(out / "fuzz_parser_seed_corpus.zip", "w") as bundle:
                bundle.writestr("valid/input.bin", b"seed")
                bundle.writestr("../outside.bin", b"escape")
            PipelineRunner._seed_corpus(out, "fuzz_parser", corpus)
            files = list(corpus.iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), b"seed")
            self.assertFalse((root / "outside.bin").exists())

    def test_fuzz_session_rejects_missing_job_build_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "a" * 12
            job = root / job_id
            artifacts = job / "artifacts"
            artifacts.mkdir(parents=True)
            for name, value in (
                (
                    "build-manifest.json",
                    {
                        "oss_fuzz_project": "parser",
                        "fuzz_targets": ["fuzz_parser"],
                        "output_directory": str(job / "build-output" / "asan"),
                    },
                ),
                ("smoke.json", {"fuzz_target": "fuzz_parser"}),
            ):
                (artifacts / name).write_text(json.dumps(value))
            runner = object.__new__(PipelineRunner)
            runner.pipeline = {
                "container_memory_mb": 1024,
                "fuzzer_rss_limit_mb": 512,
                "input_timeout_seconds": 10,
            }
            with self.assertRaisesRegex(PipelineError, "build snapshot is missing"):
                runner._fuzz_session(
                    job,
                    {},
                    seconds=1,
                    workers=1,
                    label="probe",
                )

    def test_collects_worker_stats_and_copies_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            logs = root / "logs"
            runtime.mkdir()
            logs.mkdir()
            (runtime / "fuzz-0.log").write_text(
                "stat::number_of_executed_units: 120\n"
                "stat::average_exec_per_sec: 60\n"
                "stat::peak_rss_mb: 42\n",
                encoding="utf-8",
            )
            records = PipelineRunner._collect_worker_stats(runtime, logs, "probe")
            self.assertEqual(records[0]["number_of_executed_units"], 120)
            self.assertEqual(records[0]["peak_rss_mb"], 42)
            self.assertTrue((logs / "probe-worker-0.log").is_file())

    def test_sanitizer_summaries_are_bounded_and_addresses_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "probe.log"
            log.write_text(
                "==12==ERROR: LeakSanitizer: detected memory leaks at 0x123abc\n"
                "SUMMARY: AddressSanitizer: 72 byte(s) leaked at 0xfeed\n",
                encoding="utf-8",
            )
            self.assertEqual(
                PipelineRunner._sanitizer_summaries(log),
                [
                    "==12==ERROR: LeakSanitizer: detected memory leaks at 0xADDR",
                    "SUMMARY: AddressSanitizer: 72 byte(s) leaked at 0xADDR",
                ],
            )

    def test_long_quartet_source_excerpt_is_bounded_and_keeps_original_lines(self):
        lines = [f"line {index}" for index in range(1000)]
        lines[900] = "extern int LLVMFuzzerTestOneInput(const char*, size_t) {"
        excerpt = _numbered_source_excerpt(lines, max_lines=100)
        source_rows = [row for row in excerpt.splitlines() if not row.startswith("....:")]
        self.assertLessEqual(len(source_rows), 100)
        self.assertIn("0901: extern int LLVMFuzzerTestOneInput", excerpt)
        self.assertIn("omitted]", excerpt)

    def test_quartet_discards_only_out_of_range_citations(self):
        principle = {
            "verdict": "pass",
            "rationale": "valid evidence remains",
            "evidence_lines": [2, 99999],
        }
        facts = {
            "line_count": 10,
            "entrypoint_count": 1,
            "data_reference_count": 2,
            "size_reference_count": 2,
            "unaligned_read_lines": [],
            "source_symbols": ["parse"],
            "dynamic_evidence": {
                "asan_build": True,
                "smoke_status": "passed",
                "probe_status": "passed",
                "probe_crash_count": 0,
                "probe_corpus_files": 1,
            },
        }
        review = validate_quartet_review(
            {
                "principles": {name: principle for name in ("p1", "p2", "p3", "p4")},
                "overall_verdict": "pass",
                "target_symbols": ["parse"],
                "summary": "valid",
            },
            facts,
        )
        self.assertEqual(review["principles"]["p1"]["evidence_lines"], [2])
        self.assertEqual(
            review["principles"]["p1"]["discarded_evidence_lines"], [99999]
        )

    def test_coverage_evidence_keeps_only_pinned_source_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_dir = root / "job"
            source = job_dir / "source" / "lib"
            source.mkdir(parents=True)
            (source / "parser.cc").write_text("int parse();\n", encoding="utf-8")
            (source / "fuzz_parser.cc").write_text(
                "int LLVMFuzzerTestOneInput();\n", encoding="utf-8"
            )
            evidence = build_coverage_evidence(
                job_dir,
                {"source": {"repository": "org/parser", "commit": "a" * 40}},
                {
                    "oss_fuzz_project": "parser",
                    "fuzz_targets": ["fuzz_parser"],
                },
                {
                    "fuzz_target": "fuzz_parser",
                    "elapsed_seconds": 60,
                    "corpus_files": 2,
                    "crash_files": [],
                    "worker_stats": [{"average_exec_per_sec": 100}],
                },
                [
                    {
                        "function_signature": "int parse(std::string data)",
                        "function_name": "parse",
                        "function_filename": "/src/parser/lib/parser.cc",
                        "function_arguments": ["std::string"],
                        "accummulated_complexity": 200,
                        "source_line_begin": 1,
                        "oracles": ["optimal-targets"],
                    },
                    {
                        "function_signature": "void missing()",
                        "function_filename": "/src/parser/lib/missing.cc",
                    },
                ],
                max_candidates=10,
            )
            self.assertEqual(len(evidence["gap_candidates"]), 1)
            self.assertEqual(evidence["gap_candidates"][0]["file"], "lib/parser.cc")
            self.assertEqual(evidence["gap_candidates"][0]["local_symbol_line"], 1)
            self.assertTrue(evidence["gap_candidates"][0]["direct_byte_input"])
            self.assertEqual(evidence["source_harnesses"], ["lib/fuzz_parser.cc"])
            self.assertEqual(evidence["probe"]["worker_exec_per_sec"], [100])

    def test_coverage_review_must_reference_known_target_and_candidate(self):
        evidence = {
            "built_fuzz_targets": ["fuzz_parser"],
            "gap_candidates": [{"id": "abc123"}],
        }
        review = validate_review(
            {
                "decision": "baseline_existing",
                "selected_fuzz_target": "fuzz_parser",
                "candidate_ids": ["abc123"],
                "rationale": "stateful gaps are not suitable",
                "next_actions": ["run the pinned target"],
            },
            evidence,
        )
        self.assertTrue(review["execution_ready"])
        with self.assertRaises(PipelineError):
            validate_review(
                {
                    "decision": "baseline_existing",
                    "selected_fuzz_target": "unknown",
                    "candidate_ids": [],
                },
                evidence,
            )

    def test_non_baseline_analysis_blocks_full_execution(self):
        record = analysis_record(
            {
                "built_fuzz_targets": ["fuzz_parser"],
                "gap_candidates": [{"id": "abc123"}],
            },
            {
                "decision": "generate_new_harness",
                "selected_fuzz_target": "fuzz_parser",
                "candidate_ids": ["abc123"],
                "rationale": "a deterministic parser boundary exists",
                "next_actions": ["generate a focused harness"],
            },
            {"input_tokens": 10, "cached_tokens": 0, "output_tokens": 5},
            [],
        )
        self.assertFalse(record["review"]["execution_ready"])

    def test_deterministic_gate_skips_ai_for_stateful_candidates(self):
        review = deterministic_review(
            {
                "probe": {"target": "fuzz_parser"},
                "gap_candidates": [
                    {"id": "stateful", "direct_byte_input": False}
                ],
            },
            [],
        )
        self.assertIsNotNone(review)
        self.assertEqual(review["decision"], "baseline_existing")
        self.assertIsNone(
            deterministic_review(
                {
                    "probe": {"target": "fuzz_parser"},
                    "gap_candidates": [
                        {"id": "bytes", "direct_byte_input": True}
                    ],
                },
                [],
            )
        )

    def test_full_session_uses_coverage_plan_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            (artifacts / "coverage-plan.json").write_text(
                json.dumps(
                    {"review": {"selected_fuzz_target": "fuzz_selected"}}
                ),
                encoding="utf-8",
            )
            runner = object.__new__(PipelineRunner)
            smoke = {"fuzz_target": "fuzz_smoke"}
            self.assertEqual(runner._session_target(root, smoke, "probe"), "fuzz_smoke")
            self.assertEqual(
                runner._session_target(root, smoke, "fuzz"), "fuzz_selected"
            )

    def test_full_run_requires_approved_coverage_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "a" * 12
            job_dir = root / job_id
            job_dir.mkdir()
            (job_dir / "artifacts").mkdir()
            (job_dir / "job.json").write_text("{}", encoding="utf-8")
            (job_dir / "state.json").write_text(
                json.dumps({"stage": "fuzzing", "status": "ready"}),
                encoding="utf-8",
            )
            (job_dir / "artifacts" / "quartet-review.json").write_text(
                json.dumps({"review": {"execution_ready": True}}),
                encoding="utf-8",
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root
            with self.assertRaisesRegex(PipelineError, "coverage analysis is required"):
                runner.fuzz(job_id)

    def test_full_run_rechecks_authorization_immediately_before_fuzzing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "a" * 12
            job_dir = root / job_id
            artifacts = job_dir / "artifacts"
            artifacts.mkdir(parents=True)
            (job_dir / "job.json").write_text(
                json.dumps(
                    {
                        "budgets": {"fuzz_seconds": 10},
                        "execution": {"parallel_workers": 1},
                    }
                )
            )
            (job_dir / "state.json").write_text(
                json.dumps({"stage": "fuzzing", "status": "ready", "attempts": {}})
            )
            (artifacts / "quartet-review.json").write_text(
                json.dumps({"review": {"execution_ready": True}})
            )
            (artifacts / "coverage-plan.json").write_text(
                json.dumps(
                    {
                        "review": {
                            "execution_ready": True,
                            "decision": "baseline_existing",
                        }
                    }
                )
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root
            runner.progress = lambda _message: None
            calls = []
            with patch.object(
                runner, "_recheck_policy", side_effect=lambda *_: calls.append("policy")
            ), patch.object(
                runner,
                "_fuzz_session",
                return_value={"fuzz_target": "fuzz_parser"},
            ):
                result = runner.fuzz(job_id)
            self.assertEqual(calls, ["policy"])
            self.assertEqual(result["state"]["stage"], "triage")

    def test_full_run_resumes_only_remaining_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "a" * 12
            job_dir = root / job_id
            artifacts = job_dir / "artifacts"
            artifacts.mkdir(parents=True)
            (job_dir / "job.json").write_text(
                json.dumps(
                    {
                        "budgets": {"fuzz_seconds": 10},
                        "execution": {"parallel_workers": 1},
                    }
                )
            )
            (job_dir / "state.json").write_text(
                json.dumps({"stage": "fuzzing", "status": "running", "attempts": {}})
            )
            (artifacts / "quartet-review.json").write_text(
                json.dumps({"review": {"execution_ready": True}})
            )
            (artifacts / "coverage-plan.json").write_text(
                json.dumps({"review": {"execution_ready": True}})
            )
            (artifacts / "fuzz-progress.json").write_text(
                json.dumps({"completed_seconds": 7, "sessions": []})
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root
            runner.progress = lambda _message: None
            observed = []
            with patch.object(runner, "_recheck_policy"), patch.object(
                runner,
                "_fuzz_session",
                side_effect=lambda *_args, **kwargs: (
                    observed.append(kwargs["seconds"])
                    or {"fuzz_target": "fuzz_parser", "elapsed_seconds": 3}
                ),
            ):
                result = runner.fuzz(job_id)
            self.assertEqual(observed, [3])
            self.assertEqual(result["state"]["fuzz_completed_seconds"], 10)

    def test_full_run_checkpoints_without_finishing_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "a" * 12
            job_dir = root / job_id
            artifacts = job_dir / "artifacts"
            artifacts.mkdir(parents=True)
            (job_dir / "job.json").write_text(
                json.dumps(
                    {
                        "budgets": {"fuzz_seconds": 10},
                        "execution": {"parallel_workers": 1},
                    }
                )
            )
            (job_dir / "state.json").write_text(
                json.dumps({"stage": "fuzzing", "status": "ready", "attempts": {}})
            )
            (artifacts / "quartet-review.json").write_text(
                json.dumps({"review": {"execution_ready": True}})
            )
            (artifacts / "coverage-plan.json").write_text(
                json.dumps({"review": {"execution_ready": True}})
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root
            runner.pipeline = {
                "fuzz_checkpoint_seconds": 3,
                "coverage_stall_seconds": 6,
            }
            runner.progress = lambda _message: None
            with patch.object(runner, "_recheck_policy"), patch.object(
                runner,
                "_fuzz_session",
                return_value={
                    "fuzz_target": "fuzz_parser",
                    "elapsed_seconds": 3,
                    "corpus_files": 5,
                    "executed_units": 100,
                },
            ):
                result = runner.fuzz(job_id)
            self.assertEqual(result["state"]["stage"], "fuzzing")
            self.assertEqual(result["state"]["status"], "ready")
            self.assertEqual(result["state"]["fuzz_completed_seconds"], 3)

    def test_coverage_stall_schedules_one_afl_cmplog_lane(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "d" * 12
            job_dir = root / job_id
            artifacts = job_dir / "artifacts"
            artifacts.mkdir(parents=True)
            (job_dir / "job.json").write_text(
                json.dumps(
                    {
                        "budgets": {"fuzz_seconds": 20},
                        "execution": {"parallel_workers": 1},
                    }
                )
            )
            (job_dir / "state.json").write_text(
                json.dumps({"stage": "fuzzing", "status": "ready", "attempts": {}})
            )
            (artifacts / "quartet-review.json").write_text(
                json.dumps({"review": {"execution_ready": True}})
            )
            (artifacts / "coverage-plan.json").write_text(
                json.dumps({"review": {"execution_ready": True}})
            )
            (artifacts / "fuzz-progress.json").write_text(
                json.dumps(
                    {
                        "completed_seconds": 3,
                        "last_corpus_files": 5,
                        "stalled_seconds": 3,
                        "sessions": [],
                    }
                )
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root
            runner.pipeline = {
                "fuzz_checkpoint_seconds": 3,
                "coverage_stall_seconds": 6,
                "afl_cmplog_enabled": True,
            }
            runner.progress = lambda _message: None
            with patch.object(runner, "_recheck_policy"), patch.object(
                runner,
                "_fuzz_session",
                return_value={
                    "fuzz_target": "fuzz_parser",
                    "elapsed_seconds": 3,
                    "corpus_files": 5,
                    "executed_units": 100,
                },
            ):
                result = runner.fuzz(job_id)
            self.assertEqual(result["state"]["status"], "afl_cmplog_pending")
            progress = json.loads((artifacts / "fuzz-progress.json").read_text())
            self.assertTrue(progress["coverage_stalled"])

    def test_cached_afl_result_is_accounted_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_dir = root / "org-parser-" / "job"
            artifacts = job_dir / "artifacts"
            artifacts.mkdir(parents=True)
            state_path = job_dir / "state.json"
            state = {"stage": "fuzzing", "status": "afl_cmplog_running", "attempts": {}}
            state_path.write_text(json.dumps(state))
            (artifacts / "fuzz-progress.json").write_text(
                json.dumps(
                    {
                        "completed_seconds": 10,
                        "stalled_seconds": 20,
                        "coverage_stalled": True,
                        "sessions": [],
                    }
                )
            )
            job = {"budgets": {"fuzz_seconds": 100}}
            result = {
                "status": "completed",
                "started_at": "2026-01-01T00:00:00Z",
                "completed_at": "2026-01-01T00:00:05Z",
                "requested_seconds": 5,
                "elapsed_seconds": 5,
                "new_corpus_files": 1,
                "crash_files": [],
            }
            runner = object.__new__(PipelineRunner)

            runner._apply_afl_result(job_dir, job, state_path, state, dict(result))
            recovered_state = json.loads(state_path.read_text())
            runner._apply_afl_result(
                job_dir, job, state_path, recovered_state, dict(result)
            )

            progress = json.loads((artifacts / "fuzz-progress.json").read_text())
            self.assertEqual(progress["completed_seconds"], 15)
            self.assertEqual(len(progress["sessions"]), 1)
            self.assertFalse(progress["coverage_stalled"])
            self.assertEqual(recovered_state["attempts"]["afl_cmplog"], 1)

    def test_cached_afl_crash_recovers_into_triage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "e" * 12
            job_dir = root / job_id
            artifacts = job_dir / "artifacts"
            artifacts.mkdir(parents=True)
            (job_dir / "job.json").write_text(
                json.dumps({"budgets": {"fuzz_seconds": 100}})
            )
            (job_dir / "state.json").write_text(
                json.dumps(
                    {
                        "stage": "fuzzing",
                        "status": "afl_cmplog_running",
                        "attempts": {},
                    }
                )
            )
            (artifacts / "fuzz-progress.json").write_text(
                json.dumps(
                    {
                        "completed_seconds": 10,
                        "coverage_stalled": True,
                        "sessions": [],
                    }
                )
            )
            cached_result = {
                "status": "sanitizer_finding",
                "started_at": "2026-01-01T00:00:00Z",
                "completed_at": "2026-01-01T00:00:05Z",
                "requested_seconds": 5,
                "elapsed_seconds": 5,
                "new_corpus_files": 0,
                "crash_files": ["crashes/sha256-deadbeef"],
            }
            (artifacts / "afl-cmplog-run.json").write_text(
                json.dumps(cached_result)
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root

            result = runner.afl_cmplog(job_id)

            self.assertEqual(result["state"]["stage"], "triage")
            self.assertEqual(result["state"]["status"], "triage_pending")
            self.assertEqual(
                result["state"]["triage_artifact"], "afl-cmplog-run.json"
            )
            progress = json.loads((artifacts / "fuzz-progress.json").read_text())
            self.assertEqual(progress["completed_seconds"], 15)
            self.assertTrue(progress["afl_cmplog_accounted"])

    def test_cached_optional_afl_failure_resumes_primary_fuzzer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "f" * 12
            job_dir = root / job_id
            artifacts = job_dir / "artifacts"
            artifacts.mkdir(parents=True)
            (job_dir / "job.json").write_text("{}")
            (job_dir / "state.json").write_text(
                json.dumps(
                    {
                        "stage": "fuzzing",
                        "status": "afl_cmplog_running",
                        "attempts": {},
                    }
                )
            )
            (artifacts / "afl-cmplog-run.json").write_text(
                json.dumps(
                    {
                        "status": "failed_optional_lane",
                        "error": "builder unavailable",
                    }
                )
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root

            result = runner.afl_cmplog(job_id)

            self.assertEqual(result["state"]["status"], "ready")
            self.assertIn("builder unavailable", result["state"]["last_error"])
            progress = json.loads((artifacts / "fuzz-progress.json").read_text())
            self.assertEqual(progress["afl_cmplog_status"], "failed_optional_lane")

    def test_collect_afl_outputs_deduplicates_corpus_crashes_and_hangs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime" / "target_afl_address_out" / "default"
            corpus = root / "corpus"
            crashes = root / "crashes"
            hangs = root / "hangs"
            for name in ("queue", "crashes", "hangs"):
                (runtime / name).mkdir(parents=True)
            corpus.mkdir()
            crashes.mkdir()
            hangs.mkdir()
            (runtime / "queue" / "id:000001").write_bytes(b"queue")
            (runtime / "queue" / "id:000002").symlink_to("/etc/passwd")
            (runtime / "crashes" / "id:000001").write_bytes(b"crash")
            (runtime / "crashes" / "README.txt").write_text("metadata")
            (runtime / "hangs" / "id:000001").write_bytes(b"hang")
            result = PipelineRunner._collect_afl_outputs(
                root / "runtime", corpus, crashes, hangs
            )
            self.assertEqual(result["new_corpus_files"], 1)
            self.assertEqual(len(result["crash_files"]), 1)
            self.assertEqual(len(result["hang_files"]), 1)
            self.assertEqual(len(list(corpus.iterdir())), 1)
            self.assertEqual(len(list(crashes.iterdir())), 1)
            self.assertEqual(len(list(hangs.iterdir())), 1)

    def test_afl_banner_runs_only_inside_isolated_container(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="afl-fuzz++4 test\n", stderr="help\n"
        )
        with patch(
            "fuzz_target_scout.pipeline_runner.subprocess.run",
            return_value=completed,
        ) as run:
            banner = PipelineRunner._binary_banner(Path("/tmp/afl-output"))

        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["docker", "run"])
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("/tmp/afl-output:/out:ro", command)
        self.assertEqual(command[-2:], ["/out/afl-fuzz", "-h"])
        self.assertIn("afl-fuzz++4 test", banner)

    def test_reads_embedded_afl_commit_from_pinned_oss_fuzz(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dockerfile = root / "infra" / "base-images" / "base-builder" / "Dockerfile"
            dockerfile.parent.mkdir(parents=True)
            dockerfile.write_text(
                "RUN git clone https://github.com/AFLplusplus/AFLplusplus.git aflplusplus && \\\n"
                "    git checkout " + "a" * 40 + "\n"
            )
            self.assertEqual(PipelineRunner._embedded_afl_commit(root), "a" * 40)

    def test_maps_oss_fuzz_binary_to_upstream_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            harness = source / "pdns" / "fuzz_moadnsparser.cc"
            harness.parent.mkdir()
            harness.write_text(
                "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char* data, "
                "unsigned long size) { return data && size; }\n",
                encoding="utf-8",
            )
            self.assertEqual(
                find_harness_source(source, "fuzz_target_moadnsparser"), harness
            )

    def test_quartet_review_combines_ai_and_dynamic_evidence(self):
        principle = {
            "verdict": "pass",
            "rationale": "supported by the harness",
            "evidence_lines": [1],
        }
        facts = {
            "line_count": 10,
            "entrypoint_count": 1,
            "data_reference_count": 2,
            "size_reference_count": 2,
            "unaligned_read_lines": [],
            "called_symbols": ["parse"],
            "dynamic_evidence": {
                "asan_build": True,
                "smoke_status": "passed",
                "probe_status": "passed",
                "probe_crash_count": 0,
                "probe_corpus_files": 3,
            },
        }
        review = validate_quartet_review(
            {
                "principles": {name: principle for name in ("p1", "p2", "p3", "p4")},
                "overall_verdict": "pass",
                "target_symbols": ["parse"],
                "summary": "all checks passed",
            },
            facts,
        )
        self.assertTrue(review["execution_ready"])
        self.assertEqual(review["reach_confidence"], "medium")

    def test_quartet_accepts_qualified_name_for_known_called_symbol(self):
        principle = {"verdict": "pass", "rationale": "seen", "evidence_lines": [1]}
        facts = {
            "line_count": 5,
            "entrypoint_count": 1,
            "data_reference_count": 2,
            "size_reference_count": 2,
            "unaligned_read_lines": [],
            "called_symbols": ["SetParam"],
            "dynamic_evidence": {
                "asan_build": True,
                "smoke_status": "passed",
                "probe_status": "passed",
                "probe_crash_count": 0,
                "probe_corpus_files": 1,
            },
        }
        review = validate_quartet_review(
            {
                "principles": {name: principle for name in ("p1", "p2", "p3", "p4")},
                "overall_verdict": "pass",
                "target_symbols": ["MsQuicApi::SetParam"],
                "summary": "qualified C++ name",
            },
            facts,
        )
        self.assertTrue(review["execution_ready"])

    def test_cached_quartet_result_repairs_interrupted_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "a" * 12
            job_dir = root / job_id
            artifacts = job_dir / "artifacts"
            artifacts.mkdir(parents=True)
            (job_dir / "job.json").write_text("{}")
            (job_dir / "state.json").write_text(
                json.dumps(
                    {"stage": "quartet_gate", "status": "worker_failed", "attempts": {}}
                )
            )
            (artifacts / "quartet-review.json").write_text(
                json.dumps({"review": {"execution_ready": False}})
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root
            result = runner.quartet(job_id)
            self.assertEqual(result["state"]["status"], "quartet_review_required")

    def test_failed_quartet_review_selects_and_archives_alternate_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "b" * 12
            job_dir = root / job_id
            artifacts = job_dir / "artifacts"
            runtime_probe = job_dir / "runtime-out" / "probe"
            artifacts.mkdir(parents=True)
            runtime_probe.mkdir(parents=True)
            (job_dir / "job.json").write_text("{}")
            (job_dir / "state.json").write_text(
                json.dumps({"stage": "quartet_gate", "status": "quartet_pending", "attempts": {}})
            )
            (artifacts / "build-manifest.json").write_text(
                json.dumps({"fuzz_targets": ["fuzz", "fuzz_parser"]})
            )
            for name in ("smoke.json", "probe-run.json", "quartet-review.json"):
                (artifacts / name).write_text(
                    json.dumps(
                        {"facts": {"fuzz_target": "fuzz"}, "review": {"execution_ready": False}}
                        if name == "quartet-review.json"
                        else {"fuzz_target": "fuzz"}
                    )
                )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root
            runner.pipeline = {"max_fuzz_target_attempts": 3}
            runner.progress = lambda _message: None
            result = runner.quartet(job_id)
            self.assertEqual(result["state"]["stage"], "smoke")
            self.assertEqual(result["state"]["status"], "target_retry_pending")
            self.assertEqual(result["state"]["preferred_fuzz_target"], "fuzz_parser")
            self.assertFalse((artifacts / "quartet-review.json").exists())
            history = list((artifacts / "target-history").glob("*/quartet-review.json"))
            self.assertEqual(len(history), 1)
            self.assertFalse(runtime_probe.exists())

    def test_failed_quartet_review_stops_after_target_attempt_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "c" * 12
            job_dir = root / job_id
            artifacts = job_dir / "artifacts"
            artifacts.mkdir(parents=True)
            (job_dir / "job.json").write_text("{}")
            (job_dir / "state.json").write_text(
                json.dumps(
                    {
                        "stage": "quartet_gate",
                        "status": "quartet_pending",
                        "attempts": {},
                        "attempted_fuzz_targets": ["fuzz_first"],
                    }
                )
            )
            (artifacts / "build-manifest.json").write_text(
                json.dumps({"fuzz_targets": ["fuzz_first", "fuzz_second", "fuzz_third"]})
            )
            (artifacts / "quartet-review.json").write_text(
                json.dumps(
                    {"facts": {"fuzz_target": "fuzz_second"}, "review": {"execution_ready": False}}
                )
            )
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root
            runner.pipeline = {"max_fuzz_target_attempts": 2}
            runner.progress = lambda _message: None
            result = runner.quartet(job_id)
            self.assertEqual(result["state"]["status"], "quartet_review_required")
            self.assertTrue((artifacts / "quartet-review.json").exists())


if __name__ == "__main__":
    unittest.main()
