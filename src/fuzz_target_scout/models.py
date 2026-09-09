from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class RepoSnapshot:
    full_name: str
    html_url: str
    default_branch: str
    head_sha: str
    description: str = ""
    language: str = ""
    stars: int = 0
    forks: int = 0
    size_kb: int = 0
    archived: bool = False
    disabled: bool = False
    pushed_at: str = ""
    license_name: str = ""
    topics: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    security_url: str = ""
    security_text: str = ""
    readme_excerpt: str = ""
    architecture_files: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StaticAssessment:
    fuzz_score: int
    reproduce_difficulty: int
    signals: list[str]
    blockers: list[str]
    suggested_entry_kind: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PolicyAssessment:
    status: str
    confidence: int
    source: str
    program_url: str = ""
    note: str = ""

    @property
    def handoff_allowed(self) -> bool:
        return self.status == "verified"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AIAssessment:
    fuzz_score: int
    reproduce_difficulty: int
    suggested_entry_kind: str
    rationale: str
    blockers: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ArchitectureAssessment:
    host_arch: str
    compatible: bool
    confidence: int
    evidence: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Candidate:
    repo: RepoSnapshot
    static: StaticAssessment
    policy: PolicyAssessment
    final_score: int
    architecture: ArchitectureAssessment | None = None
    ai: AIAssessment | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo.to_dict(),
            "static": self.static.to_dict(),
            "policy": self.policy.to_dict(),
            "final_score": self.final_score,
            "architecture": self.architecture.to_dict() if self.architecture else None,
            "ai": self.ai.to_dict() if self.ai else None,
        }
