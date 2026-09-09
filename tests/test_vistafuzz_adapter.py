import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzz_target_scout.vistafuzz_adapter import VistaFuzzAdapter


class VistaFuzzAdapterTests(unittest.TestCase):
    def test_inspects_pinned_opencv_artifact_without_claiming_generic_support(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "tools" / "vistafuzz"
            testing = tool / "OpenCV-Testing"
            (tool / ".git").mkdir(parents=True)
            (testing / "API").mkdir(parents=True)
            (testing / "tool").mkdir()
            (testing / "Dockerfile").write_text("FROM scratch")
            (testing / "main.py").write_text("pass")
            (testing / "tool" / "API_info.py").write_text("API = {}")
            (testing / "API" / "OpenCV_API_filtered_subset.json").write_text(
                json.dumps([{"name": "cv.test"}])
            )
            commit = "a" * 40
            lock = root / "toolchain.lock.json"
            lock.write_text(json.dumps({
                "schema_version": 1,
                "tools": {"vistafuzz": {"commit": commit}},
            }))
            config = {"pipeline": {
                "tools_path": str(root / "tools"),
                "toolchain_lock_path": str(lock),
                "runs_path": str(root / "runs"),
            }}
            with patch("fuzz_target_scout.vistafuzz_adapter._capture", return_value=commit):
                result = VistaFuzzAdapter(config).inspect()
            self.assertEqual(result["api_count"], 1)
            self.assertTrue(result["api_format_valid"])
            self.assertFalse(result["generic_python_support"])
            self.assertFalse(result["bounty_evidence_eligible"])

    def test_reports_recoverable_upstream_metadata_format_error(self):
        from fuzz_target_scout.vistafuzz_adapter import _api_metadata_status

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "apis.json"
            path.write_text('["cv2.resize" "cv2.imread",]')
            count, valid = _api_metadata_status(path)
            self.assertEqual(count, 2)
            self.assertFalse(valid)


if __name__ == "__main__":
    unittest.main()
