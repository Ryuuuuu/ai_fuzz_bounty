import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.pipeline import PipelineError
from fuzz_target_scout.pipeline_runner import PipelineRunner, _select_smoke_target


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


if __name__ == "__main__":
    unittest.main()
