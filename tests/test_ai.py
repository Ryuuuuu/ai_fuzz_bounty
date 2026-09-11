import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.ai import CodexReviewer
from fuzz_target_scout.engine import _completed_repositories, _enabled_language_queries


class CodexReviewerTests(unittest.TestCase):
    def test_discovery_queries_follow_enabled_pipeline_languages(self):
        selected = _enabled_language_queries(
            [
                "archived:false language:C",
                "archived:false language:C++",
                "archived:false language:Rust",
                "stars:20..100",
            ],
            ["C", "C++"],
        )

        self.assertEqual(
            selected,
            [
                "archived:false language:C",
                "archived:false language:C++",
                "stars:20..100",
            ],
        )

    def test_completed_repositories_are_excluded_from_future_ai_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory)
            completed = runs / "org-done-aaaaaaaaaaaa"
            active = runs / "org-active-bbbbbbbbbbbb"
            completed.mkdir()
            active.mkdir()
            (completed / "state.json").write_text(
                json.dumps({"stage": "complete"}), encoding="utf-8"
            )
            (completed / "job.json").write_text(
                json.dumps({"source": {"repository": "Org/Done"}}),
                encoding="utf-8",
            )
            (active / "state.json").write_text(
                json.dumps({"stage": "fuzzing"}), encoding="utf-8"
            )
            (active / "job.json").write_text(
                json.dumps({"source": {"repository": "Org/Active"}}),
                encoding="utf-8",
            )

            repositories = _completed_repositories(runs)

        self.assertEqual(repositories, {"org/done"})

    def test_uses_logged_in_cli_with_requested_model_and_high_reasoning(self):
        with tempfile.TemporaryDirectory() as directory:
            schema = Path(directory) / "schema.json"
            schema.write_text('{"type":"object"}', encoding="utf-8")
            reviewer = CodexReviewer(
                {
                    "executable": "codex",
                    "model": "gpt-daybreak-blue-latest",
                    "reasoning_effort": "high",
                    "prompt_version": "test-v1",
                    "timeout_seconds": 30,
                    "schema_path": str(schema),
                }
            )
            captured = {}

            def fake_run(command, **kwargs):
                captured["command"] = command
                captured["input"] = kwargs["input"]
                captured["env"] = kwargs["env"]
                output_path = Path(
                    command[command.index("--output-last-message") + 1]
                )
                output_path.write_text(
                    json.dumps(
                        {
                            "assessments": [
                                {
                                    "repository": "org/tool",
                                    "fuzz_score": 81,
                                    "reproduce_difficulty": 2,
                                    "suggested_entry_kind": "existing_harness",
                                    "rationale": "Existing local harness and deterministic input.",
                                    "blockers": [],
                                }
                            ]
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
                            "usage": {
                                "input_tokens": 100,
                                "cached_input_tokens": 80,
                                "output_tokens": 20,
                            },
                        }
                    ),
                    stderr="",
                )

            secret_environment = {
                "GITHUB_TOKEN": "github-secret",
                "GH_TOKEN": "gh-secret",
                "OPENAI_API_KEY": "openai-secret",
                "CODEX_API_KEY": "codex-secret",
                "PATH": "/usr/bin",
            }
            with patch.dict("fuzz_target_scout.ai.os.environ", secret_environment, clear=True):
                with patch(
                    "fuzz_target_scout.ai.shutil.which", return_value="/usr/bin/codex"
                ):
                    with patch(
                        "fuzz_target_scout.ai.subprocess.run", side_effect=fake_run
                    ):
                        result, usage = reviewer.assess({"repository": "org/tool"})

            command = captured["command"]
            self.assertEqual(
                command[command.index("--model") + 1],
                "gpt-daybreak-blue-latest",
            )
            self.assertIn("model_reasoning_effort=high", command)
            self.assertIn("read-only", command)
            self.assertIn("--ephemeral", command)
            self.assertIn("--skip-git-repo-check", command)
            self.assertEqual(result.fuzz_score, 81)
            self.assertEqual(usage["cached_tokens"], 80)
            self.assertNotIn("OPENAI_API_KEY", captured["input"])
            self.assertEqual(captured["env"], {"PATH": "/usr/bin"})


if __name__ == "__main__":
    unittest.main()
