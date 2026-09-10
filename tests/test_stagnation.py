import json
import tempfile
import unittest
from pathlib import Path

from fuzz_target_scout.pipeline_runner import PipelineRunner
from fuzz_target_scout.stagnation import generate_dictionary


class StagnationTests(unittest.TestCase):
    def test_generates_content_addressed_libfuzzer_dictionary(self):
        with tempfile.TemporaryDirectory() as directory:
            job = Path(directory)
            artifacts = job / "artifacts"
            output = job / "build-output" / "asan"
            source = job / "source"
            artifacts.mkdir()
            output.mkdir(parents=True)
            source.mkdir()
            (source / "parser.cc").write_text(
                'if (kind == "application/example") parse("MAGIC_HEADER");\n'
            )
            (artifacts / "build-manifest.json").write_text(json.dumps({
                "output_directory": str(output)
            }))
            first = generate_dictionary(job, "fuzz_parser")
            second = generate_dictionary(job, "fuzz_parser")
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertGreaterEqual(first["token_count"], 2)
            text = (output / "fuzz_parser.dict").read_text()
            self.assertIn("MAGIC_HEADER", text)

    def test_native_second_stall_uses_an_alternate_pinned_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            job = Path(directory)
            artifacts = job / "artifacts"
            source = job / "source"
            artifacts.mkdir()
            (source / "first").mkdir(parents=True)
            (source / "second").mkdir(parents=True)
            (source / "first" / "fuzz.cc").write_text(
                'extern "C" int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long);\n'
            )
            (source / "second" / "fuzz.cc").write_text(
                'extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, unsigned long size) { return size; }\n'
            )
            (artifacts / "generic-integration.json").write_text(json.dumps({
                "candidate": {"file": "first/fuzz.cc"}
            }))
            plan = {
                "review": {
                    "decision": "baseline_existing",
                    "execution_ready": True,
                    "selected_fuzz_target": "generic_fuzzer",
                },
                "evidence": {
                    "execution_mode": "native_container",
                    "source_harnesses": ["first/fuzz.cc", "second/fuzz.cc"],
                    "gap_candidates": [],
                },
            }
            path = artifacts / "coverage-plan.json"
            path.write_text(json.dumps(plan))
            runner = object.__new__(PipelineRunner)

            self.assertTrue(runner._schedule_stagnation_harness(job))
            updated = json.loads(path.read_text())

        candidate = updated["evidence"]["gap_candidates"][0]
        self.assertEqual(candidate["file"], "second/fuzz.cc")
        self.assertEqual(candidate["candidate_kind"], "alternate_upstream_harness")
        self.assertEqual(updated["review"]["candidate_ids"], [candidate["id"]])

    def test_native_second_stall_rejects_a_stateful_network_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            job = Path(directory)
            artifacts = job / "artifacts"
            source = job / "source"
            artifacts.mkdir()
            source.mkdir()
            (source / "recvfuzz.cpp").write_text(
                'extern "C" int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long) { '
                'CreateLoopbackDatapath(); return 0; }\n'
            )
            (artifacts / "generic-integration.json").write_text(json.dumps({
                "candidate": {"file": "current.cc"}
            }))
            path = artifacts / "coverage-plan.json"
            path.write_text(json.dumps({
                "review": {"decision": "baseline_existing", "execution_ready": True},
                "evidence": {
                    "execution_mode": "native_container",
                    "source_harnesses": ["recvfuzz.cpp"],
                    "gap_candidates": [],
                },
            }))
            runner = object.__new__(PipelineRunner)

            self.assertFalse(runner._schedule_stagnation_harness(job))
            updated = json.loads(path.read_text())

        self.assertEqual(updated["evidence"]["gap_candidates"], [])
        self.assertEqual(updated["review"]["decision"], "baseline_existing")

    def test_second_stall_selects_a_known_coverage_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            job = Path(directory)
            artifacts = job / "artifacts"
            artifacts.mkdir()
            plan = {
                "review": {"decision": "baseline_sufficient", "execution_ready": True},
                "evidence": {"gap_candidates": [{"id": "candidate-1"}]},
            }
            path = artifacts / "coverage-plan.json"
            path.write_text(json.dumps(plan))
            runner = object.__new__(PipelineRunner)
            self.assertTrue(runner._schedule_stagnation_harness(job))
            updated = json.loads(path.read_text())
            self.assertEqual(updated["review"]["decision"], "generate_new_harness")
            self.assertEqual(updated["review"]["candidate_ids"], ["candidate-1"])


if __name__ == "__main__":
    unittest.main()
