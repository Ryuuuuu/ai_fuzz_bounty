from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from fuzz_target_scout.config import load_config


class ConfigTests(unittest.TestCase):
    def test_automatic_resource_settings_remain_dynamic_until_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.toml"
            config_path.write_text(
                "[pipeline]\nparallel_workers = 0\ncontainer_memory_mb = 0\n",
                encoding="utf-8",
            )
            config, _ = load_config(config_path)

        self.assertEqual(config["pipeline"]["parallel_workers"], 0)
        self.assertEqual(config["pipeline"]["container_memory_mb"], 0)

    def test_packaged_inputs_match_repository_inputs(self) -> None:
        root = Path(__file__).resolve().parents[1]
        package = root / "src" / "fuzz_target_scout" / "resources"
        pairs = [
            (root / "catalog.json", package / "catalog.json"),
            (root / "toolchain.lock.json", package / "toolchain.lock.json"),
            (root / "oss-fuzz-support.json", package / "oss-fuzz-support.json"),
        ]
        pairs.extend(
            (path, package / "schemas" / path.name)
            for path in (root / "schemas").glob("*.json")
        )
        for source, bundled in pairs:
            self.assertEqual(
                json.loads(source.read_text(encoding="utf-8")),
                json.loads(bundled.read_text(encoding="utf-8")),
            )

    def test_defaults_use_packaged_read_only_inputs_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, config_path = load_config(Path(directory) / "missing.toml")

        self.assertFalse(config_path.exists())
        for section, key in (
            ("policy", "catalog_path"),
            ("ai", "schema_path"),
            ("pipeline", "toolchain_lock_path"),
            ("pipeline", "oss_fuzz_index_path"),
            ("pipeline", "coverage_schema_path"),
            ("pipeline", "quartet_schema_path"),
            ("pipeline", "triage_schema_path"),
        ):
            path = Path(config[section][key])
            self.assertTrue(path.is_file(), path)
            self.assertIn("resources", path.parts)

    def test_explicit_missing_input_path_is_not_silently_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.toml"
            config_path.write_text(
                '[policy]\ncatalog_path = "private-catalog.json"\n',
                encoding="utf-8",
            )
            config, _ = load_config(config_path)

        self.assertEqual(
            Path(config["policy"]["catalog_path"]),
            root / "private-catalog.json",
        )


if __name__ == "__main__":
    unittest.main()
