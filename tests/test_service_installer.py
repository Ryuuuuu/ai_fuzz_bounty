from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


class ServiceInstallerTests(unittest.TestCase):
    def test_installer_generates_a_portable_user_service_without_secrets(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "install_central_agent_service.sh"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            scripts = root / "scripts"
            scripts.mkdir(parents=True)
            installer = scripts / source.name
            shutil.copy2(source, installer)
            installer.chmod(0o755)
            launcher = root / ".venv" / "bin" / "fuzz-pipeline"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            launcher.chmod(0o755)
            (root / "config.toml").write_text("[pipeline]\n", encoding="utf-8")
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            systemctl = fake_bin / "systemctl"
            systemctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            systemctl.chmod(0o755)
            config_home = Path(directory) / "config"
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
            environment["XDG_CONFIG_HOME"] = str(config_home)
            completed = subprocess.run(
                [str(installer)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=environment,
                timeout=10,
                check=False,
            )
            unit = (
                config_home / "systemd" / "user" / "fuzz-central-agent.service"
            ).read_text(encoding="utf-8")
            secret_file = config_home / "ai-fuzz-bounty" / "agent.env"
            secret_mode = stat.S_IMODE(secret_file.stat().st_mode)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(str(launcher), unit)
        self.assertIn(" agent", unit)
        self.assertIn(f"Environment=PATH={root}/.venv/bin:", unit)
        self.assertNotIn("FUZZ_TELEGRAM_BOT_TOKEN=123", unit)
        self.assertEqual(secret_mode, 0o600)


if __name__ == "__main__":
    unittest.main()
