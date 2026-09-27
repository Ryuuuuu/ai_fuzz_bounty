import unittest

from fuzz_target_scout.yield_policy import evaluate_campaign_yield


class YieldPolicyTests(unittest.TestCase):
    def test_shallow_campaign_rotates_after_minimum_observation(self):
        result = evaluate_campaign_yield(
            {"coverage_edges": 530, "coverage_features": 2500},
            {
                "completed_seconds": 7200,
                "sessions": [
                    {"accounted_seconds": 3600, "coverage_edges": 532, "coverage_features": 2534},
                    {"accounted_seconds": 3600, "coverage_edges": 532, "coverage_features": 2534},
                ],
            },
            {},
        )
        self.assertEqual(result["reason"], "shallow_reach")
        self.assertEqual(result["metrics"]["edge_growth"], 2)

    def test_growing_deep_campaign_continues(self):
        result = evaluate_campaign_yield(
            {"coverage_edges": 800, "coverage_features": 1000},
            {
                "completed_seconds": 7200,
                "sessions": [
                    {"accounted_seconds": 3600, "coverage_edges": 820, "coverage_features": 1050},
                    {"accounted_seconds": 3600, "coverage_edges": 850, "coverage_features": 1100},
                ],
            },
            {},
        )
        self.assertIsNone(result)

    def test_deep_campaign_rotates_after_six_hours_without_progress(self):
        result = evaluate_campaign_yield(
            {"coverage_edges": 1000, "coverage_features": 1500},
            {
                "completed_seconds": 25200,
                "sessions": [
                    {"accounted_seconds": 3600, "coverage_edges": 1100, "coverage_features": 1600},
                    {"accounted_seconds": 21600, "coverage_edges": 1100, "coverage_features": 1600},
                ],
            },
            {},
        )
        self.assertEqual(result["reason"], "coverage_stagnation")
        self.assertEqual(result["metrics"]["trailing_stagnation_seconds"], 21600)

    def test_policy_can_be_disabled(self):
        result = evaluate_campaign_yield(
            {"coverage_edges": 1},
            {"completed_seconds": 86400, "sessions": []},
            {"low_yield_rotation_enabled": False},
        )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
