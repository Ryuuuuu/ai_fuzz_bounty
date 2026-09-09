from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fuzz_target_scout.resources import (
    ResourceSnapshot,
    detect_system_resources,
    plan_resources,
)
from fuzz_target_scout.pipeline import PipelineError


class ResourceTests(unittest.TestCase):
    def test_detection_honors_cgroup_v2_cpu_and_memory_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            cgroup = root / "cgroup"
            (proc / "self").mkdir(parents=True)
            constrained = cgroup / "job.slice"
            constrained.mkdir(parents=True)
            (proc / "meminfo").write_text(
                "MemTotal:       16777216 kB\nMemAvailable:   12582912 kB\n",
                encoding="utf-8",
            )
            (proc / "self" / "cgroup").write_text(
                "0::/job.slice\n", encoding="utf-8"
            )
            (constrained / "cpu.max").write_text(
                "250000 100000\n", encoding="utf-8"
            )
            (constrained / "memory.max").write_text(
                str(4 * 1024**3), encoding="utf-8"
            )
            (constrained / "memory.current").write_text(
                str(1 * 1024**3), encoding="utf-8"
            )

            detected = detect_system_resources(
                proc_root=proc,
                cgroup_root=cgroup,
                inspect_docker=False,
            )

        self.assertEqual(detected.cpu_count, 2)
        self.assertEqual(detected.memory_total_mb, 4096)
        self.assertEqual(detected.memory_available_mb, 3072)
        self.assertIn("cgroup_cpu=2", detected.sources)

    def test_parallel_plan_reserves_host_capacity_and_avoids_overcommit(self):
        snapshot = ResourceSnapshot(
            cpu_count=12,
            memory_total_mb=8090,
            memory_available_mb=7155,
            sources=("test",),
        )

        allocation = plan_resources({}, snapshot=snapshot)

        self.assertEqual(allocation.parallel_jobs, 3)
        self.assertEqual(allocation.workers_per_job, 2)
        self.assertEqual(allocation.container_memory_mb, 1920)
        self.assertEqual(allocation.fuzzer_rss_limit_mb, 768)
        self.assertLessEqual(
            allocation.parallel_jobs * allocation.container_memory_mb,
            snapshot.memory_available_mb - allocation.memory_reserve_mb,
        )
        self.assertLessEqual(
            allocation.parallel_jobs * allocation.workers_per_job,
            snapshot.cpu_count - allocation.cpu_reserve,
        )

    def test_detection_preserves_too_small_cgroup_memory_for_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            cgroup = root / "cgroup"
            (proc / "self").mkdir(parents=True)
            constrained = cgroup / "small.slice"
            constrained.mkdir(parents=True)
            (proc / "meminfo").write_text(
                "MemTotal:       16777216 kB\nMemAvailable:   12582912 kB\n",
                encoding="utf-8",
            )
            (proc / "self" / "cgroup").write_text(
                "0::/small.slice\n", encoding="utf-8"
            )
            (constrained / "memory.max").write_text(
                str(384 * 1024**2), encoding="utf-8"
            )
            (constrained / "memory.current").write_text(
                str(64 * 1024**2), encoding="utf-8"
            )

            detected = detect_system_resources(
                proc_root=proc,
                cgroup_root=cgroup,
                inspect_docker=False,
            )

        self.assertEqual(detected.memory_total_mb, 384)
        self.assertEqual(detected.memory_available_mb, 320)
        with self.assertRaisesRegex(PipelineError, "at least 512 MB"):
            plan_resources({}, snapshot=detected)

    def test_single_job_receives_more_workers_from_the_same_machine(self):
        snapshot = ResourceSnapshot(
            cpu_count=12,
            memory_total_mb=8090,
            memory_available_mb=7155,
            sources=("test",),
        )

        allocation = plan_resources({}, requested_jobs=1, snapshot=snapshot)

        self.assertEqual(allocation.parallel_jobs, 1)
        self.assertEqual(allocation.workers_per_job, 6)
        self.assertEqual(allocation.container_memory_mb, 4992)

    def test_plan_refuses_an_environment_too_small_for_isolated_fuzzing(self):
        snapshot = ResourceSnapshot(2, 384, 384, ("test",))
        with self.assertRaisesRegex(PipelineError, "at least 512 MB"):
            plan_resources({}, snapshot=snapshot)


if __name__ == "__main__":
    unittest.main()
