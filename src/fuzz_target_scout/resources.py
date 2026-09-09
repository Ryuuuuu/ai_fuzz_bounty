from __future__ import annotations

import math
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .pipeline import PipelineError


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    cpu_count: int
    memory_total_mb: int
    memory_available_mb: int
    sources: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["sources"] = list(self.sources)
        return value


@dataclass(frozen=True, slots=True)
class ResourceAllocation:
    parallel_jobs: int
    workers_per_job: int
    container_memory_mb: int
    fuzzer_rss_limit_mb: int
    cpu_reserve: int
    memory_reserve_mb: int
    detected: ResourceSnapshot

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["detected"] = self.detected.as_dict()
        return value


def detect_system_resources(
    *,
    proc_root: Path = Path("/proc"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    inspect_docker: bool = True,
) -> ResourceSnapshot:
    """Return the effective Linux resources visible to local fuzz containers."""
    sources: list[str] = []
    cpu_limits: list[int] = []
    try:
        affinity_count = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        affinity_count = os.cpu_count() or 1
    cpu_limits.append(max(1, affinity_count))
    sources.append(f"cpu_affinity={max(1, affinity_count)}")

    cgroup_roots = _cgroup_roots(proc_root, cgroup_root)
    cgroup_cpu_limits = [
        value
        for root in cgroup_roots
        if (value := _cgroup_cpu_limit(root)) is not None
    ]
    if cgroup_cpu_limits:
        cgroup_cpu = min(cgroup_cpu_limits)
        cpu_limits.append(cgroup_cpu)
        sources.append(f"cgroup_cpu={cgroup_cpu}")

    memory = _read_meminfo(proc_root / "meminfo")
    memory_total_mb = max(512, memory.get("MemTotal", 4096 * 1024) // 1024)
    memory_available_mb = max(
        256,
        memory.get("MemAvailable", memory_total_mb * 1024) // 1024,
    )
    sources.extend(
        (
            f"proc_memory_total_mb={memory_total_mb}",
            f"proc_memory_available_mb={memory_available_mb}",
        )
    )

    cgroup_memory_limits = [
        value
        for root in cgroup_roots
        if (value := _cgroup_memory_capacity(root)) is not None
    ]
    if cgroup_memory_limits:
        limit_mb = min(value[0] for value in cgroup_memory_limits)
        available_mb = min(value[1] for value in cgroup_memory_limits)
        memory_total_mb = min(memory_total_mb, limit_mb)
        memory_available_mb = min(memory_available_mb, available_mb)
        sources.append(f"cgroup_memory_limit_mb={limit_mb}")
        sources.append(f"cgroup_memory_available_mb={available_mb}")

    docker_capacity = _docker_capacity() if inspect_docker else None
    if docker_capacity:
        docker_cpu, docker_memory_mb = docker_capacity
        cpu_limits.append(docker_cpu)
        memory_total_mb = min(memory_total_mb, docker_memory_mb)
        memory_available_mb = min(memory_available_mb, docker_memory_mb)
        sources.append(f"docker_cpu={docker_cpu}")
        sources.append(f"docker_memory_mb={docker_memory_mb}")

    return ResourceSnapshot(
        cpu_count=max(1, min(cpu_limits)),
        memory_total_mb=max(1, memory_total_mb),
        memory_available_mb=max(1, min(memory_total_mb, memory_available_mb)),
        sources=tuple(sources),
    )


def plan_resources(
    pipeline: dict[str, Any],
    *,
    requested_jobs: int | None = None,
    snapshot: ResourceSnapshot | None = None,
) -> ResourceAllocation:
    snapshot = snapshot or detect_system_resources(
        inspect_docker=bool(pipeline.get("inspect_docker_resources", True))
    )
    if snapshot.memory_available_mb < 512:
        raise PipelineError("fuzzing requires at least 512 MB of available memory")
    cpu_reserve = min(
        max(0, int(pipeline.get("resource_cpu_reserve", 1))),
        max(0, snapshot.cpu_count - 1),
    )
    requested_memory_reserve = max(
        0, int(pipeline.get("resource_memory_reserve_mb", 1024))
    )
    memory_reserve = min(
        requested_memory_reserve,
        max(0, snapshot.memory_available_mb - 512),
    )
    usable_cpu = max(1, snapshot.cpu_count - cpu_reserve)
    usable_memory = max(512, snapshot.memory_available_mb - memory_reserve)

    minimum_workers = max(1, int(pipeline.get("min_workers_per_job", 2)))
    worker_memory = max(256, int(pipeline.get("memory_per_fuzz_worker_mb", 768)))
    container_overhead = max(
        128, int(pipeline.get("container_memory_overhead_mb", 384))
    )
    minimum_container = max(
        512,
        int(pipeline.get("min_container_memory_mb", 1024)),
        container_overhead + minimum_workers * worker_memory,
    )
    automatic_job_cap = max(1, int(pipeline.get("auto_parallel_job_cap", 4)))
    configured_job_cap = int(pipeline.get("max_parallel_jobs", 0))
    parallel_jobs = min(
        automatic_job_cap,
        max(1, usable_cpu // minimum_workers),
        max(1, usable_memory // minimum_container),
    )
    if configured_job_cap > 0:
        parallel_jobs = min(parallel_jobs, configured_job_cap)
    if requested_jobs is not None and requested_jobs > 0:
        parallel_jobs = min(parallel_jobs, requested_jobs)
    parallel_jobs = max(1, parallel_jobs)

    memory_share = max(512, usable_memory // parallel_jobs)
    configured_memory = int(pipeline.get("container_memory_mb", 0))
    if 0 < configured_memory < 512:
        raise PipelineError("container_memory_mb must be 0 or at least 512")
    if configured_memory > 0:
        memory_share = min(memory_share, configured_memory)
    worker_cap = int(pipeline.get("parallel_workers", 0))
    if worker_cap <= 0:
        worker_cap = max(1, int(pipeline.get("max_workers_per_job", 6)))
    memory_worker_limit = max(1, (memory_share - container_overhead) // worker_memory)
    workers = max(
        1,
        min(worker_cap, max(1, usable_cpu // parallel_jobs), memory_worker_limit),
    )
    container_memory = min(
        memory_share,
        max(512, container_overhead + workers * worker_memory),
    )
    configured_rss = max(256, int(pipeline.get("fuzzer_rss_limit_mb", 1024)))
    rss_limit = max(
        256,
        min(
            configured_rss,
            max(256, (container_memory - container_overhead) // workers),
        ),
    )
    return ResourceAllocation(
        parallel_jobs=parallel_jobs,
        workers_per_job=workers,
        container_memory_mb=container_memory,
        fuzzer_rss_limit_mb=rss_limit,
        cpu_reserve=cpu_reserve,
        memory_reserve_mb=memory_reserve,
        detected=snapshot,
    )


def _read_meminfo(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return values
    for line in lines:
        if ":" not in line:
            continue
        key, remainder = line.split(":", 1)
        fields = remainder.split()
        if fields and fields[0].isdigit():
            values[key] = int(fields[0])
    return values


def _read_integer(path: Path) -> int | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not value or value == "max":
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _cgroup_roots(proc_root: Path, cgroup_root: Path) -> list[Path]:
    roots = [cgroup_root]
    try:
        lines = (proc_root / "self" / "cgroup").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return roots
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        controllers = fields[1].split(",") if fields[1] else []
        relative = Path(fields[2].lstrip("/"))
        if relative.is_absolute() or ".." in relative.parts:
            continue
        candidates = [cgroup_root / relative]
        for controller in controllers:
            candidates.append(cgroup_root / controller / relative)
        if "cpu" in controllers or "cpuacct" in controllers:
            candidates.append(cgroup_root / "cpu,cpuacct" / relative)
        for candidate in candidates:
            if candidate not in roots:
                roots.append(candidate)
    return roots


def _cgroup_cpu_limit(root: Path) -> int | None:
    try:
        fields = (root / "cpu.max").read_text(encoding="utf-8").split()
    except OSError:
        fields = []
    if len(fields) == 2 and fields[0] != "max":
        try:
            quota, period = int(fields[0]), int(fields[1])
            if quota > 0 and period > 0:
                return max(1, math.floor(quota / period))
        except ValueError:
            pass
    for cpu_root in (root / "cpu", root / "cpu,cpuacct", root):
        quota = _read_integer(cpu_root / "cpu.cfs_quota_us")
        period = _read_integer(cpu_root / "cpu.cfs_period_us")
        if quota and period:
            return max(1, math.floor(quota / period))
    return None


def _cgroup_memory_capacity(root: Path) -> tuple[int, int] | None:
    pairs = (
        (root / "memory.max", root / "memory.current"),
        (
            root / "memory" / "memory.limit_in_bytes",
            root / "memory" / "memory.usage_in_bytes",
        ),
    )
    for limit_path, usage_path in pairs:
        limit = _read_integer(limit_path)
        usage = _read_integer(usage_path) or 0
        if limit is None or limit >= 1 << 60:
            continue
        limit_mb = max(1, limit // 1024**2)
        available_mb = max(1, (limit - min(limit, usage)) // 1024**2)
        return limit_mb, available_mb
    return None


def _docker_capacity() -> tuple[int, int] | None:
    if not shutil.which("docker"):
        return None
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    fields = result.stdout.split()
    if result.returncode != 0 or len(fields) != 2:
        return None
    try:
        cpu_count, memory_bytes = int(fields[0]), int(fields[1])
    except ValueError:
        return None
    if cpu_count < 1 or memory_bytes < 256 * 1024**2:
        return None
    return cpu_count, memory_bytes // 1024**2
