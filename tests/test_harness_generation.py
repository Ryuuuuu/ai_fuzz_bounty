import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.harness_generation import (
    extract_harness_code,
    generation_prompt,
    select_generation_candidate,
    source_context,
    validate_generated_harness,
)
from fuzz_target_scout.pipeline import PipelineError
from fuzz_target_scout.pipeline_runner import PipelineRunner


class HarnessGenerationTests(unittest.TestCase):
    def test_selects_only_candidate_requested_by_coverage_plan(self):
        plan = {
            "review": {
                "decision": "generate_new_harness",
                "candidate_ids": ["chosen"],
            },
            "evidence": {
                "gap_candidates": [
                    {"id": "other", "signature": "other()"},
                    {"id": "chosen", "signature": "parse()"},
                ]
            },
        }
        self.assertEqual(select_generation_candidate(plan)["signature"], "parse()")
        plan["review"]["decision"] = "baseline_existing"
        with self.assertRaises(PipelineError):
            select_generation_candidate(plan)

    def test_context_is_bounded_and_cannot_escape_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            target = source / "lib" / "parser.cc"
            target.parent.mkdir()
            target.write_text("\n".join(f"line {i}" for i in range(1, 301)))
            context = source_context(
                source,
                {"file": "lib/parser.cc", "local_symbol_line": 150},
                radius=2,
            )
            self.assertIn("00148: line 148", context)
            self.assertIn("00152: line 152", context)
            with self.assertRaises(PipelineError):
                source_context(
                    source,
                    {"file": "../outside.cc", "local_symbol_line": 1},
                )

    def test_extracts_and_validates_generated_harness(self):
        response = """```cpp
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  return parse(data, size);
}
```"""
        code = extract_harness_code(response)
        validation = validate_generated_harness(
            code, {"signature": "int parse(const uint8_t*, size_t)"}
        )
        self.assertEqual(validation["target_symbol"], "parse")
        with self.assertRaises(PipelineError):
            validate_generated_harness(
                code.replace("parse(data, size)", "connect(0, 0, 0)"),
                {"signature": "int connect(int, int, int)"},
            )

    def test_repair_prompt_contains_only_compressed_failure_context(self):
        prompt = generation_prompt(
            project="parser",
            language="C++",
            fuzz_target="fuzz_parser",
            candidate={
                "signature": "int parse(const uint8_t*, size_t)",
                "file": "lib/parser.cc",
                "local_symbol_line": 10,
            },
            context="target context",
            existing_harness="existing harness",
            prior_code="candidate code",
            build_error="x" * 9000,
        )
        self.assertIn("previous_candidate", prompt)
        self.assertNotIn("x" * 8001, prompt)

    def test_archives_old_evidence_and_resets_mutable_run_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            job = Path(directory)
            artifacts = job / "artifacts"
            artifacts.mkdir()
            for name in (
                "smoke.json",
                "probe-run.json",
                "quartet-review.json",
                "coverage-plan.json",
            ):
                (artifacts / name).write_text(json.dumps({"name": name}))
            (job / "runtime-out" / "probe").mkdir(parents=True)
            for category in ("corpus", "crashes"):
                path = job / category / "fuzz_parser"
                path.mkdir(parents=True)
                (path / "sample").write_bytes(b"data")
            PipelineRunner._archive_pre_generation_results(job, "fuzz_parser")
            self.assertFalse((artifacts / "coverage-plan.json").exists())
            self.assertTrue(list((artifacts / "history").glob("*/coverage-plan.json")))
            self.assertFalse((job / "corpus" / "fuzz_parser").exists())
            self.assertFalse((job / "crashes" / "fuzz_parser").exists())

    def test_generation_returns_successful_build_to_smoke_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_id = "org-parser-" + "a" * 12
            job = root / "runs" / job_id
            artifacts = job / "artifacts"
            source = job / "source"
            build_source = job / "build-source"
            for path in (artifacts, source / "lib", build_source / "lib"):
                path.mkdir(parents=True, exist_ok=True)
            harness = (
                '#include <cstdint>\nextern "C" int LLVMFuzzerTestOneInput('
                "const uint8_t* data, size_t size) { return old_parse(data, size); }\n"
            )
            (source / "lib" / "fuzz_parser.cc").write_text(harness)
            (build_source / "lib" / "fuzz_parser.cc").write_text(harness)
            (source / "lib" / "parser.cc").write_text(
                "int parse(const uint8_t* data, size_t size) { return size; }\n"
            )
            work_order = {
                "source": {"repository": "org/parser", "language": "C++"},
                "route": {
                    "required_tools": [
                        {"name": "oss-fuzz-gen", "commit": "b" * 40}
                    ]
                },
                "ai": {"max_harness_attempts": 3},
            }
            (job / "job.json").write_text(json.dumps(work_order))
            (job / "state.json").write_text(
                json.dumps(
                    {
                        "stage": "fuzzing",
                        "status": "harness_work_pending",
                        "attempts": {},
                    }
                )
            )
            plan = {
                "review": {
                    "decision": "generate_new_harness",
                    "candidate_ids": ["candidate"],
                    "selected_fuzz_target": "fuzz_parser",
                },
                "evidence": {
                    "gap_candidates": [
                        {
                            "id": "candidate",
                            "signature": "int parse(const uint8_t*, size_t)",
                            "file": "lib/parser.cc",
                            "local_symbol_line": 1,
                        }
                    ]
                },
            }
            for name, value in (
                (
                    "build-manifest.json",
                    {
                        "oss_fuzz_project": "parser",
                        "fuzz_targets": ["fuzz_parser"],
                    },
                ),
                ("smoke.json", {"fuzz_target": "fuzz_parser"}),
                ("probe-run.json", {"fuzz_target": "fuzz_parser"}),
                ("quartet-review.json", {"review": {"execution_ready": True}}),
                ("coverage-plan.json", plan),
            ):
                (artifacts / name).write_text(json.dumps(value))
            runner = object.__new__(PipelineRunner)
            runner.runs_root = root / "runs"
            runner.tools_root = root / "tools"
            (runner.tools_root / "oss-fuzz-gen").mkdir(parents=True)
            runner.pipeline = {}
            generated = """```cpp
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  return parse(data, size);
}
```"""
            with patch.object(runner, "_capture", return_value="b" * 40), patch.object(
                runner, "_build_fuzzers"
            ), patch(
                "fuzz_target_scout.pipeline_runner.invoke_oss_fuzz_gen_adapter",
                return_value=(generated, {"input_tokens": 10}),
            ):
                result = runner.generate(job_id)
            state = json.loads((job / "state.json").read_text())
            self.assertEqual(state["stage"], "smoke")
            self.assertEqual(result["attempts"][0]["success"], True)
            self.assertIn(
                "parse(data, size)",
                (build_source / "lib" / "fuzz_parser.cc").read_text(),
            )
            self.assertFalse((artifacts / "coverage-plan.json").exists())
            self.assertTrue((artifacts / "harness-generation.json").is_file())


if __name__ == "__main__":
    unittest.main()
