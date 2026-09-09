import json
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
from fuzz_target_scout.pipeline import PipelineError
from fuzz_target_scout.pipeline_runner import PipelineRunner, _select_smoke_target
from fuzz_target_scout.quartet_gate import find_harness_source, validate_quartet_review


class PipelineRunnerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
