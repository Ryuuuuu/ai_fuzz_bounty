import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.oss_fuzz_gen_codex import main


class OssFuzzGenCodexAdapterTests(unittest.TestCase):
    def test_writes_expected_rawoutput_and_strips_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = root / "prompt.txt"
            response = root / "responses"
            prompt.write_text("write one harness", encoding="utf-8")
            captured = {}

            def fake_run(command, **kwargs):
                captured["command"] = command
                captured["env"] = kwargs["env"]
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text("```c\nint harness;\n```", encoding="utf-8")
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(
                        {
                            "type": "turn.completed",
                            "usage": {
                                "input_tokens": 30,
                                "cached_input_tokens": 10,
                                "output_tokens": 8,
                            },
                        }
                    ),
                    stderr="",
                )

            environment = {
                "PATH": "/usr/bin",
                "GITHUB_TOKEN": "secret",
                "GH_TOKEN": "secret",
                "OPENAI_API_KEY": "secret",
                "CODEX_API_KEY": "secret",
                "CODEX_ADAPTER_SAMPLE_CAP": "1",
            }
            with patch.dict(os.environ, environment, clear=True):
                with patch(
                    "fuzz_target_scout.oss_fuzz_gen_codex.shutil.which",
                    return_value="/usr/bin/codex",
                ):
                    with patch(
                        "fuzz_target_scout.oss_fuzz_gen_codex.subprocess.run",
                        side_effect=fake_run,
                    ):
                        status = main(
                            [
                                "-model=ignored",
                                f"-prompt={prompt}",
                                f"-response={response}",
                                "-max-tokens=1000",
                                "-expected-samples=4",
                                "-temperature=0.4",
                            ]
                        )

            self.assertEqual(status, 0)
            self.assertTrue((response / "01.rawoutput").is_file())
            self.assertFalse((response / "02.rawoutput").exists())
            usage = json.loads((response / "codex-usage.json").read_text())
            self.assertEqual(usage["generated_samples"], 1)
            self.assertEqual(usage["usage"][0]["input_tokens"], 30)
            self.assertNotIn("GITHUB_TOKEN", captured["env"])
            self.assertNotIn("OPENAI_API_KEY", captured["env"])
            self.assertEqual(captured["command"][0], "codex")


if __name__ == "__main__":
    unittest.main()
