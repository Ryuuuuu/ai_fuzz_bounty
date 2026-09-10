from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fuzz_target_scout.adaptive_strategy import (
    activate_runtime_strategy,
    attempted_strategies,
    current_strategy,
    evaluate_runtime_strategy,
    inject_dictionary_seeds,
    load_strategy_record,
    queue_strategy,
    runtime_arguments,
)


class AdaptiveStrategyTests(unittest.TestCase):
    def test_value_profile_is_queued_activated_and_evaluated_once(self):
        with tempfile.TemporaryDirectory() as directory:
            job = Path(directory)
            (job / "artifacts").mkdir()
            queued = queue_strategy(job, "enable_value_profile", "stalled", 600)
            progress = {
                "completed_seconds": 1000,
                "last_coverage_edges": 20,
                "last_coverage_features": 30,
                "last_corpus_files": 10,
            }

            active = activate_runtime_strategy(job, progress)
            self.assertEqual(active["id"], queued["id"])
            self.assertEqual(runtime_arguments(job), ["-use_value_profile=1"])

            progress["completed_seconds"] = 1600
            evaluated = evaluate_runtime_strategy(
                job, progress, coverage_advanced=False
            )
            record = load_strategy_record(job)

        self.assertEqual(evaluated["status"], "ineffective")
        self.assertEqual(
            attempted_strategies(record), {"enable_value_profile"}
        )

    def test_dictionary_strategy_adds_bounded_content_addressed_seeds(self):
        with tempfile.TemporaryDirectory() as directory:
            job = Path(directory)
            artifacts = job / "artifacts"
            corpus = job / "corpus"
            artifacts.mkdir()
            corpus.mkdir()
            dictionary = job / "target.dict"
            dictionary.write_text('"HELLO"\nname="WORLD"\n', encoding="utf-8")
            queue_strategy(job, "inject_dictionary_seeds", "stalled", 300)
            activate_runtime_strategy(job, {"completed_seconds": 0})

            first = inject_dictionary_seeds(job, dictionary, corpus)
            second = inject_dictionary_seeds(job, dictionary, corpus)
            entry = current_strategy(load_strategy_record(job))

        self.assertEqual(first, 3)
        self.assertEqual(second, 0)
        self.assertEqual(entry["seed_files_added"], 3)


if __name__ == "__main__":
    unittest.main()
