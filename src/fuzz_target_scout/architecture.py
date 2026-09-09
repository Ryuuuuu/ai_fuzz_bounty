from __future__ import annotations

import platform
import re
from typing import Any

from .models import ArchitectureAssessment, RepoSnapshot


ARCH_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86-64": "x86_64",
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "armv8": "aarch64",
}

ARCH_PATTERNS = {
    "x86_64": re.compile(r"(?i)(?:x86[_-]?64|amd64|linux/amd64)"),
    "aarch64": re.compile(r"(?i)(?:aarch64|arm64|armv8(?:\.\d+)?|linux/arm64)"),
}

NEGATIVE_PATTERNS = {
    "x86_64": re.compile(
        r"(?i)(?:x86[_-]?64|amd64)\s+(?:is\s+)?(?:not\s+supported|unsupported)"
    ),
    "aarch64": re.compile(
        r"(?i)(?:aarch64|arm64|armv8)\s+(?:is\s+)?(?:not\s+supported|unsupported)"
    ),
}


def normalize_architecture(value: str) -> str:
    normalized = value.strip().casefold().replace(" ", "")
    return ARCH_ALIASES.get(normalized, normalized)


def resolve_host_architecture(config: dict[str, Any] | None = None) -> str:
    configured = str((config or {}).get("host_arch") or "auto")
    if configured.casefold() == "auto":
        configured = platform.machine()
    return normalize_architecture(configured)


def assess_architecture(
    repo: RepoSnapshot, config: dict[str, Any]
) -> ArchitectureAssessment:
    host_arch = resolve_host_architecture(config)
    if str(config.get("mode") or "native_only") != "native_only":
        return ArchitectureAssessment(
            host_arch=host_arch,
            compatible=True,
            confidence=50,
            evidence=["architecture_mode:any"],
        )
    matcher = ARCH_PATTERNS.get(host_arch)
    negative = NEGATIVE_PATTERNS.get(host_arch)
    if matcher is None:
        return ArchitectureAssessment(
            host_arch=host_arch,
            compatible=False,
            confidence=100,
            blockers=[f"unsupported_host_architecture:{host_arch}"],
        )

    evidence: list[str] = []
    blockers: list[str] = []
    sources = {
        "repository": "\n".join((repo.description, " ".join(repo.topics))),
        "README": repo.readme_excerpt,
        **repo.architecture_files,
    }
    for source, source_text in sources.items():
        for line in source_text.splitlines():
            compact = " ".join(line.strip().split())
            if not compact:
                continue
            if negative and negative.search(compact):
                blockers.append(f"{source}:{compact[:220]}")
            elif matcher.search(compact):
                evidence.append(f"{source}:{compact[:220]}")
            if len(evidence) >= 12 and len(blockers) >= 4:
                break

    for path in repo.paths:
        if matcher.search(path):
            evidence.append(f"path:{path[:240]}")
        if len(evidence) >= 16:
            break

    evidence = list(dict.fromkeys(evidence))[:16]
    blockers = list(dict.fromkeys(blockers))[:8]
    require_explicit = bool(config.get("require_explicit_support", True))
    compatible = not blockers and (bool(evidence) or not require_explicit)
    if not evidence and require_explicit:
        blockers.append(f"no_explicit_native_support_evidence:{host_arch}")
    return ArchitectureAssessment(
        host_arch=host_arch,
        compatible=compatible,
        confidence=100 if blockers else (90 if evidence else 50),
        evidence=evidence,
        blockers=blockers,
    )
