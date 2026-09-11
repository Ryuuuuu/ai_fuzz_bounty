from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Callable

from .ai import AIError, CodexReviewer, compact_evidence, evidence_hash
from .architecture import assess_architecture
from .github import GitHubClient, GitHubError
from .models import Candidate, RepoSnapshot
from .policy import PolicyVerifier
from .scoring import assess_static, final_score
from .storage import Store, make_ai_cache_key


Progress = Callable[[str], None]


@dataclass(slots=True)
class ScanSummary:
    scan_id: int
    discovered: int
    verified: int
    conditional: int
    needs_review: int
    rejected: int
    ai_calls: int
    ai_cache_hits: int
    errors: int
    architecture_compatible: int = 0
    architecture_rejected: int = 0


class ScoutEngine:
    def __init__(self, config: dict[str, Any], progress: Progress | None = None):
        self.config = config
        self.progress = progress or (lambda _: None)
        github_config = {
            **config["github"],
            "max_architecture_files": config["architecture"]["max_evidence_files"],
        }
        self.github = GitHubClient(github_config)
        self.policy = PolicyVerifier(
            config["policy"]["catalog_path"],
            int(config["policy"]["max_catalog_age_days"]),
        )
        self.store = Store(config["storage"]["database_path"])

    def close(self) -> None:
        self.store.close()

    def scan(
        self,
        *,
        catalog_only: bool = False,
        limit: int | None = None,
        queries: list[str] | None = None,
        use_ai: bool = True,
    ) -> ScanSummary:
        source = "catalog" if catalog_only else "github-search"
        scan_id = self.store.start_scan(source)
        candidates: list[Candidate] = []
        errors = 0
        try:
            repos = self._discover(catalog_only, limit, queries)
            self.progress(f"discovered {len(repos)} unique repositories")
            for index, repo in enumerate(repos, 1):
                self.progress(f"[{index}/{len(repos)}] policy {repo.full_name}")
                try:
                    with_policy = self.github.load_security_policy(repo)
                    policy = self.policy.verify(with_policy)
                    if policy.status in {"verified", "conditional"}:
                        self.progress(f"[{index}/{len(repos)}] code evidence {repo.full_name}")
                        with_policy = self.github.hydrate_code_evidence(with_policy)
                    architecture = assess_architecture(
                        with_policy, self.config["architecture"]
                    )
                    static = assess_static(with_policy)
                    if not architecture.compatible:
                        static.blockers.extend(
                            value for value in architecture.blockers
                            if value not in static.blockers
                        )
                    else:
                        static.signals.append(
                            f"host_arch_compatible:{architecture.host_arch}"
                        )
                    candidates.append(
                        Candidate(
                            repo=with_policy,
                            static=static,
                            policy=policy,
                            final_score=final_score(static),
                            architecture=architecture,
                        )
                    )
                except GitHubError as exc:
                    errors += 1
                    self.progress(f"warning: {repo.full_name}: {exc}")

            ai_calls, ai_cache_hits, ai_errors = self._apply_ai(candidates, use_ai)
            errors += ai_errors
            for candidate in candidates:
                self.store.upsert_candidate(candidate, scan_id)

            counts = {
                status: sum(c.policy.status == status for c in candidates)
                for status in ("verified", "conditional", "needs_review", "rejected")
            }
            self.store.finish_scan(
                scan_id,
                "completed_with_errors" if errors else "completed",
                len(repos),
                counts["verified"],
                f"{errors} repository or AI errors" if errors else "",
            )
            return ScanSummary(
                scan_id=scan_id,
                discovered=len(repos),
                verified=counts["verified"],
                conditional=counts["conditional"],
                needs_review=counts["needs_review"],
                rejected=counts["rejected"],
                ai_calls=ai_calls,
                ai_cache_hits=ai_cache_hits,
                errors=errors,
                architecture_compatible=sum(
                    bool(c.architecture and c.architecture.compatible)
                    for c in candidates
                ),
                architecture_rejected=sum(
                    bool(c.architecture and not c.architecture.compatible)
                    for c in candidates
                ),
            )
        except Exception as exc:
            self.store.finish_scan(
                scan_id, "failed", len(candidates), 0, str(exc)[:1000]
            )
            raise

    def _discover(
        self,
        catalog_only: bool,
        limit: int | None,
        queries: list[str] | None,
    ) -> list[RepoSnapshot]:
        unique: dict[str, RepoSnapshot] = {}
        if catalog_only:
            names = self.policy.catalog_names[:limit] if limit else self.policy.catalog_names
            for name in names:
                try:
                    repo = self.github.get_repository(name)
                except GitHubError as exc:
                    self.progress(f"warning: catalog lookup {name}: {exc}")
                    continue
                if repo:
                    unique[repo.full_name.casefold()] = repo
            return list(unique.values())

        if bool(self.config["github"].get("seed_policy_catalog", True)):
            for name in self.policy.catalog_names:
                try:
                    repo = self.github.get_repository(name)
                except GitHubError as exc:
                    self.progress(f"warning: catalog seed {name}: {exc}")
                    continue
                if repo:
                    unique.setdefault(repo.full_name.casefold(), repo)
                if limit and len(unique) >= limit:
                    return list(unique.values())
        selected_queries = _enabled_language_queries(
            queries or list(self.config["github"]["queries"]),
            (self.config.get("pipeline") or {}).get("languages", []),
        )
        per_query = int(self.config["github"]["per_query"])
        pushed_after = (date.today() - timedelta(days=365)).isoformat()
        for query_template in selected_queries:
            query = query_template.replace("{pushed_after}", pushed_after)
            self.progress(f"search: {query}")
            for repo in self.github.search_repositories(query, per_query):
                unique.setdefault(repo.full_name.casefold(), repo)
                if limit and len(unique) >= limit:
                    return list(unique.values())
        values = list(unique.values())
        return values[:limit] if limit else values

    def _apply_ai(
        self, candidates: list[Candidate], use_ai: bool
    ) -> tuple[int, int, int]:
        ai_config = self.config["ai"]
        if not use_ai or not ai_config["enabled"]:
            return 0, 0, 0
        reviewer = CodexReviewer(ai_config)
        if not reviewer.available:
            self.progress(
                f"AI skipped: Codex CLI executable '{reviewer.executable}' was not found"
            )
            return 0, 0, 0

        enabled_languages = {
            str(value).casefold()
            for value in (self.config.get("pipeline") or {}).get("languages", [])
        }
        completed_repositories = _completed_repositories(
            Path((self.config.get("pipeline") or {}).get("runs_path", "data/runs"))
        )
        eligible = [
            candidate
            for candidate in candidates
            if candidate.policy.status == "verified"
            and bool(candidate.architecture and candidate.architecture.compatible)
            and candidate.static.fuzz_score >= int(ai_config["minimum_static_score"])
            and (
                not enabled_languages
                or candidate.repo.language.casefold() in enabled_languages
            )
            and candidate.repo.full_name.casefold() not in completed_repositories
        ]
        eligible.sort(key=lambda item: item.static.fuzz_score, reverse=True)
        eligible = eligible[: int(ai_config["max_candidates_per_scan"])]
        calls = 0
        cache_hits = 0
        errors = 0
        pending: list[tuple[Candidate, dict[str, Any], str]] = []

        for candidate in eligible:
            evidence = compact_evidence(
                candidate.repo,
                candidate.static,
                candidate.policy.status,
                candidate.architecture,
            )
            digest = evidence_hash(evidence)
            cache_key = make_ai_cache_key(
                candidate.repo.full_name,
                candidate.repo.head_sha,
                reviewer.model,
                reviewer.prompt_version,
                digest,
            )
            cached = self.store.get_ai_cache(cache_key)
            if cached:
                candidate.ai = cached
                candidate.final_score = final_score(candidate.static, cached)
                cache_hits += 1
                continue
            pending.append((candidate, evidence, cache_key))

        if not pending:
            return calls, cache_hits, errors

        names = ", ".join(item[0].repo.full_name for item in pending)
        self.progress(f"AI batch review ({len(pending)}): {names}")
        try:
            assessments, usage = reviewer.assess_batch(
                [item[1] for item in pending]
            )
        except AIError as exc:
            errors += 1
            self.progress(f"warning: AI batch review failed: {exc}")
            return calls, cache_hits, errors

        calls = 1
        usage_share = {
            key: round(value / len(pending))
            for key, value in usage.items()
        }
        for candidate, _evidence, cache_key in pending:
            assessment = assessments[candidate.repo.full_name]
            candidate.ai = assessment
            candidate.final_score = final_score(candidate.static, assessment)
            self.store.put_ai_cache(
                cache_key,
                candidate.repo.full_name,
                candidate.repo.head_sha,
                reviewer.model,
                reviewer.prompt_version,
                assessment,
                usage_share,
            )
        return calls, cache_hits, errors


def _completed_repositories(runs_root: Path) -> set[str]:
    completed: set[str] = set()
    if not runs_root.is_dir() or runs_root.is_symlink():
        return completed
    for state_path in runs_root.glob("*/state.json"):
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if state.get("stage") != "complete":
                continue
            job = json.loads(
                (state_path.parent / "job.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            continue
        repository = str((job.get("source") or {}).get("repository") or "")
        if repository:
            completed.add(repository.casefold())
    return completed


def _enabled_language_queries(
    queries: list[str], enabled_languages: list[str]
) -> list[str]:
    enabled = {str(value).casefold() for value in enabled_languages}
    if not enabled:
        return queries
    selected = []
    for query in queries:
        match = re.search(r"(?:^|\s)language:([^\s]+)", query, re.IGNORECASE)
        if not match or match.group(1).casefold() in enabled:
            selected.append(query)
    return selected
