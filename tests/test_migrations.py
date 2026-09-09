import json
import tempfile
import unittest
from pathlib import Path

from fuzz_target_scout.migrations import migrate_runs


class MigrationTests(unittest.TestCase):
    def test_migrates_v1_with_backup_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = root / "org-parser-aaaaaaaaaaaa"
            job.mkdir()
            state = job / "state.json"
            state.write_text(json.dumps({"schema_version": 1, "status": "ready"}))
            first = migrate_runs(root)
            self.assertEqual(first["migrated"], [job.name])
            self.assertEqual(json.loads(state.read_text())["schema_version"], 2)
            self.assertTrue((job / "state.v1.json").is_file())
            second = migrate_runs(root)
            self.assertEqual(second["already_current"], [job.name])

    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = root / "org-parser-aaaaaaaaaaaa"
            job.mkdir()
            state = job / "state.json"
            state.write_text(json.dumps({"schema_version": 1}))
            result = migrate_runs(root, dry_run=True)
            self.assertEqual(result["migrated"], [job.name])
            self.assertEqual(json.loads(state.read_text())["schema_version"], 1)
