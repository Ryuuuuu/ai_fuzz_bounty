from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .ai import AIError, CodexReviewer, compact_evidence, evidence_hash
from .architecture import assess_architecture, resolve_host_architecture
from .arm_preflight import (
    ArmPreflight, MESON_PREFLIGHT_VERSION, PREFLIGHT_VERSION,
    TRANSIENT_FAILURE_REASONS,
)
from .github import GitHubClient, GitHubError
from .models import ArchitectureAssessment, Candidate, RepoSnapshot
from .pipeline import CPP_LANGUAGES, _generic_build_signal
from .policy import PolicyVerifier
from .scoring import assess_static, final_score
from .storage import Store, make_ai_cache_key


Progress = Callable[[str], None]

REPO_COOLDOWN_FAILURE_REASONS = frozenset({
    "native_build_or_smoke_failed", "smoke_marker_missing", "no_root_cmake_build",
})


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
    arm_preflight_attempted: int = 0
    arm_preflight_passed: int = 0


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
        exclude_repositories: set[str] | None = None,
        search_pages_per_query: int = 1,
        run_arm_preflight: bool = False,
        seed_repositories: Iterable[str] | None = None,
        arm_preflight_max_attempts: int | None = None,
        arm_preflight_budget_seconds: int | None = None,
        arm_preflight_stop_after_success: bool = False,
    ) -> ScanSummary:
        source = "catalog" if catalog_only else "github-search"
        scan_id = self.store.start_scan(source)
        candidates: list[Candidate] = []
        errors = 0
        try:
            self._refresh_policy_sources()
            excluded = {
                str(value).casefold() for value in (exclude_repositories or set())
            }
            if excluded:
                self.progress(
                    f"excluded {len(excluded)} previously selected repositories"
                )
            lookup_errors: list[str] = []
            repos = self._discover(
                catalog_only, limit, queries, excluded, search_pages_per_query,
                seed_repositories=seed_repositories, lookup_errors=lookup_errors,
            )
            errors += len(lookup_errors)
            self.progress(f"discovered {len(repos)} unique repositories")
            for index, repo in enumerate(repos, 1):
                self.progress(f"[{index}/{len(repos)}] policy {repo.full_name}")
                try:
                    with_policy = self.github.load_security_policy(repo)
                    external_url = self.policy.external_security_url_for(
                        repo.full_name
                    )
                    if external_url:
                        with_policy = self.github.load_curated_security_policy(
                            with_policy, external_url
                        )
                    policy = self.policy.verify(with_policy)
                    if policy.status in {"verified", "conditional"}:
                        self.progress(f"[{index}/{len(repos)}] code evidence {repo.full_name}")
                        with_policy = self.github.hydrate_code_evidence(with_policy)
                        policy = self.policy.verify(with_policy)
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

            arm_attempted, arm_passed = (
                self._preflight_arm_candidates(
                    candidates,
                    max_attempts=arm_preflight_max_attempts,
                    budget_seconds=arm_preflight_budget_seconds,
                    stop_after_success=arm_preflight_stop_after_success,
                )
                if run_arm_preflight else (0, 0)
            )
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
                arm_preflight_attempted=arm_attempted,
                arm_preflight_passed=arm_passed,
            )
        except Exception as exc:
            self.store.finish_scan(
                scan_id, "failed", len(candidates), 0, str(exc)[:1000]
            )
            raise

    def _refresh_policy_sources(self) -> None:
        policy_config = self.config["policy"]
        if not bool(policy_config.get("google_oss_vrp_feed_enabled", True)):
            return
        try:
            text = self.github.get_repository_file(
                str(
                    policy_config.get("google_oss_vrp_feed_repository")
                    or "google/bughunters"
                ),
                str(
                    policy_config.get("google_oss_vrp_feed_path")
                    or "oss-repository-tier/external_repositories.txtpb"
                ),
                str(policy_config.get("google_oss_vrp_feed_branch") or "main"),
            )
        except GitHubError as exc:
            self.progress(f"warning: Google OSS VRP scope refresh failed: {exc}")
            return
        count = self.policy.merge_google_oss_vrp_feed(
            text,
            str(policy_config.get("google_oss_vrp_program_url") or ""),
        )
        self.progress(f"loaded {count} repositories from the Google OSS VRP scope feed")

    def _discover(
        self,
        catalog_only: bool,
        limit: int | None,
        queries: list[str] | None,
        excluded: set[str] | None = None,
        search_pages_per_query: int = 1,
        seed_repositories: Iterable[str] | None = None,
        lookup_errors: list[str] | None = None,
    ) -> list[RepoSnapshot]:
        excluded = excluded or set()
        unique: dict[str, RepoSnapshot] = {}
        enabled_languages = [
            str(value)
            for value in (self.config.get("pipeline") or {}).get("languages", [])
        ]
        if catalog_only:
            for name in self.policy.catalog_names:
                if name.casefold() in excluded:
                    continue
                try:
                    repo = self.github.get_repository(name)
                except GitHubError as exc:
                    self.progress(f"warning: catalog lookup {name}: {exc}")
                    continue
                if repo:
                    if not _language_is_enabled(repo.language, enabled_languages):
                        continue
                    unique[repo.full_name.casefold()] = repo
                    if limit and len(unique) >= limit:
                        break
            return list(unique.values())

        for name in seed_repositories or ():
            if name.casefold() in excluded or name.casefold() in unique:
                continue
            try:
                repo = self.github.get_repository(name)
            except GitHubError as exc:
                self.progress(f"warning: backlog lookup {name}: {exc}")
                if lookup_errors is not None:
                    lookup_errors.append(name)
                continue
            if repo and repo.full_name.casefold() not in excluded and _language_is_enabled(
                repo.language, enabled_languages
            ):
                unique.setdefault(repo.full_name.casefold(), repo)
                if limit and len(unique) >= limit:
                    return list(unique.values())

        if bool(self.config["github"].get("seed_policy_catalog", True)):
            for name in self.policy.catalog_names:
                if name.casefold() in excluded or name.casefold() in unique:
                    continue
                try:
                    repo = self.github.get_repository(name)
                except GitHubError as exc:
                    self.progress(f"warning: catalog seed {name}: {exc}")
                    continue
                if repo:
                    if not _language_is_enabled(repo.language, enabled_languages):
                        continue
                    unique.setdefault(repo.full_name.casefold(), repo)
                if limit and len(unique) >= limit:
                    return list(unique.values())
        configured_queries = list(
            queries if queries is not None else self.config["github"]["queries"]
        )
        if queries is None:
            configured_queries.extend(self.config["github"].get("additional_queries", []))
        selected_queries = _enabled_language_queries(
            list(dict.fromkeys(configured_queries)),
            (self.config.get("pipeline") or {}).get("languages", []),
        )
        per_query = int(self.config["github"]["per_query"])
        max_pages = max(1, int(self.config["github"].get("max_search_pages", 1)))
        pushed_after = (date.today() - timedelta(days=365)).isoformat()
        for query_template in selected_queries:
            query = query_template.replace("{pushed_after}", pushed_after)
            for _ in range(min(max_pages, max(1, search_pages_per_query))):
                page = self.store.get_search_page(query_template, max_pages)
                self.progress(f"search page {page}: {query}")
                results = self.github.search_repositories(
                    query,
                    per_query,
                    start_page=page,
                )
                self.store.advance_search_page(
                    query_template,
                    page,
                    had_results=bool(results),
                    max_pages=max_pages,
                )
                for repo in results:
                    if repo.full_name.casefold() in excluded or not _language_is_enabled(
                        repo.language, enabled_languages
                    ):
                        continue
                    unique.setdefault(repo.full_name.casefold(), repo)
                    if limit and len(unique) >= limit:
                        return list(unique.values())
                if not results:
                    break
        values = list(unique.values())
        return values[:limit] if limit else values

    @staticmethod
    def _arm_preflight_version(candidate: Candidate) -> str | None:
        markers: set[str] = set()
        for signal in candidate.static.signals:
            value = str(signal).casefold()
            if value.startswith("standard_build:"):
                markers.update(value.split(":", 1)[1].split(","))
        # The preflight itself makes the same choice after checking the pinned
        # checkout. Preserve the CMake cache key for repositories with both.
        if "cmakelists.txt" in markers:
            return PREFLIGHT_VERSION
        if "meson.build" in markers:
            return MESON_PREFLIGHT_VERSION
        return None

    @staticmethod
    def _accept_arm_preflight(candidate: Candidate, evidence: str) -> None:
        candidate.architecture = ArchitectureAssessment(
            host_arch="aarch64",
            compatible=True,
            confidence=95,
            evidence=[evidence],
        )
        candidate.static.blockers = [
            blocker for blocker in candidate.static.blockers
            if blocker not in {
                "no_explicit_native_support_evidence:aarch64",
                "native_build_probe_required:aarch64",
            }
        ]
        signal = "host_arch_compatible:aarch64"
        if signal not in candidate.static.signals:
            candidate.static.signals.append(signal)

    def _preflight_arm_candidates(
        self,
        candidates: list[Candidate],
        *,
        max_attempts: int | None = None,
        budget_seconds: int | None = None,
        stop_after_success: bool = False,
    ) -> tuple[int, int]:
        architecture = self.config["architecture"]
        if (
            not bool(architecture.get("arm_preflight_enabled", True))
            or resolve_host_architecture(architecture) != "aarch64"
        ):
            return 0, 0
        minimum_score = int(self.config["scoring"]["minimum_handoff_score"])
        maximum_kb = min(
            100000, max(1, int(architecture.get("arm_preflight_max_repository_kb", 50000)))
        )
        retry_hours = max(0, int(architecture.get("arm_preflight_failure_retry_hours", 24)))
        transient_retry_seconds = min(retry_hours * 3600, 15 * 60)
        pending: list[tuple[bool, bool, Candidate, str]] = []
        passed = 0
        for candidate in candidates:
            assessment = candidate.architecture
            if (
                candidate.policy.status != "verified"
                or candidate.repo.language.casefold() not in {"c", "c++"}
                or assessment is None
                or not (
                    assessment.compatible
                    or assessment.blockers in (
                        ["no_explicit_native_support_evidence:aarch64"],
                        ["native_build_probe_required:aarch64"],
                    )
                )
            ):
                continue
            # Architecture labels alone do not prove the native C/C++ builder
            # can compile a pinned checkout. Require this current-commit probe.
            assessment.compatible = False
            # Replace the temporary lack-of-documentation blocker so this same
            # candidate can be retried once its cooldown has elapsed.
            assessment.blockers = [
                blocker for blocker in assessment.blockers
                if blocker != "no_explicit_native_support_evidence:aarch64"
            ]
            probe_blocker = "native_build_probe_required:aarch64"
            if probe_blocker not in assessment.blockers:
                assessment.blockers.append(probe_blocker)
            if probe_blocker not in candidate.static.blockers:
                candidate.static.blockers.append(probe_blocker)
            version = self._arm_preflight_version(candidate)
            if (
                not candidate.policy.program_url
                or not candidate.repo.security_url
                or candidate.final_score < minimum_score
                or version is None
            ):
                continue
            build_system = "cmake" if version == PREFLIGHT_VERSION else "meson"
            smoke = "ctest" if build_system == "cmake" else "meson_test"
            expected_evidence = (
                f"native_arm_preflight:{version}:{build_system}_build_{smoke}:"
                f"{candidate.repo.head_sha.casefold()}"
            )
            cached = self.store.get_arm_preflight(
                candidate.repo.full_name, candidate.repo.head_sha,
                "aarch64", version,
            )
            if cached and cached["passed"] and cached["evidence"] == expected_evidence:
                self._accept_arm_preflight(candidate, expected_evidence)
                passed += 1
                continue
            repository_kb = (
                candidate.repo.source_tree_kb
                if candidate.repo.source_tree_kb is not None
                else candidate.repo.size_kb
            )
            if not 0 < repository_kb <= maximum_kb:
                continue
            if cached and not cached["passed"]:
                try:
                    checked = datetime.fromisoformat(str(cached["checked_at"]))
                    if checked.tzinfo is None:
                        checked = checked.replace(tzinfo=timezone.utc)
                    age = datetime.now(timezone.utc) - checked
                    retry_seconds = (
                        transient_retry_seconds
                        if cached["reason"] in TRANSIENT_FAILURE_REASONS
                        else retry_hours * 3600
                    )
                    if age.total_seconds() < retry_seconds:
                        continue
                except ValueError:
                    pass
            if cached is None and retry_hours:
                latest = self.store.get_latest_arm_preflight(
                    candidate.repo.full_name, "aarch64", version,
                )
                if (
                    latest
                    and latest["head_sha"].casefold() != candidate.repo.head_sha.casefold()
                    and not latest["passed"]
                    and latest["reason"] in REPO_COOLDOWN_FAILURE_REASONS
                ):
                    try:
                        checked = datetime.fromisoformat(str(latest["checked_at"]))
                        if checked.tzinfo is None:
                            checked = checked.replace(tzinfo=timezone.utc)
                        age = datetime.now(timezone.utc) - checked
                        if 0 <= age.total_seconds() < retry_hours * 3600:
                            self.progress(
                                "ARM preflight deferred after recent repository "
                                f"build failure: {candidate.repo.full_name}"
                            )
                            continue
                    except ValueError:
                        pass
            pending.append((
                self.store.has_prior_successful_arm_preflight(
                    candidate.repo.full_name, candidate.repo.head_sha,
                    "aarch64", version,
                ),
                self.store.has_prior_failed_arm_preflight(
                    candidate.repo.full_name, "aarch64"
                ),
                candidate,
                version,
            ))

        if stop_after_success and passed:
            return 0, passed
        pending.sort(
            key=lambda item: (
                not item[0],
                item[1],
                item[2].policy.source != "catalog",
                (
                    item[2].repo.source_tree_kb
                    if item[2].repo.source_tree_kb is not None
                    else item[2].repo.size_kb
                ),
                -item[2].final_score,
                item[2].repo.full_name.casefold(),
            )
        )
        configured_maximum = max(0, int(architecture.get("arm_preflight_max_per_scan", 2)))
        maximum = min(8, configured_maximum if max_attempts is None else max(0, max_attempts))
        deadline = (
            time.monotonic() + max(60, budget_seconds)
            if budget_seconds is not None else None
        )
        attempted = 0
        for _prior_success, _prior_failure, candidate, version in pending[:maximum]:
            remaining = None if deadline is None else int(deadline - time.monotonic())
            if remaining is not None and remaining < 60:
                self.progress("ARM preflight deferred: discovery time budget exhausted")
                break
            runner_config = architecture if remaining is None else {
                **architecture,
                "arm_preflight_timeout_seconds": min(
                    int(architecture.get("arm_preflight_timeout_seconds", 900)),
                    remaining,
                ),
            }
            runner = ArmPreflight(runner_config, progress=self.progress)
            self.progress(f"ARM preflight: {candidate.repo.full_name}")
            result = runner.check(candidate.repo)
            attempted += 1
            self.store.put_arm_preflight(
                candidate.repo.full_name, candidate.repo.head_sha,
                "aarch64", version,
                passed=result.passed, reason=result.reason, evidence=result.evidence,
            )
            if result.passed and result.evidence == (
                f"native_arm_preflight:{version}:"
                f"{'cmake_build_ctest' if version == PREFLIGHT_VERSION else 'meson_build_meson_test'}:"
                f"{candidate.repo.head_sha.casefold()}"
            ):
                self._accept_arm_preflight(candidate, result.evidence)
                passed += 1
                self.progress(f"ARM preflight passed: {candidate.repo.full_name}")
                if stop_after_success:
                    break
            else:
                detail = (
                    f"; {result.evidence}"
                    if result.evidence.startswith("native_arm_failure:") else ""
                )
                self.progress(
                    f"ARM preflight did not pass: {candidate.repo.full_name} "
                    f"({result.reason}{detail})"
                )
        return attempted, passed

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
        pipeline_config = self.config.get("pipeline") or {}
        planned_repositories = _planned_repositories(
            Path(pipeline_config.get("runs_path", "data/runs"))
        )
        architecture_config = pipeline_config.get("architecture")
        native_build_signal_required = (
            architecture_config is not None
            and resolve_host_architecture(architecture_config) != "x86_64"
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
            and candidate.repo.full_name.casefold() not in planned_repositories
            and (
                not native_build_signal_required
                or candidate.repo.language.casefold() not in CPP_LANGUAGES
                or _generic_build_signal({"signals": candidate.static.signals})
                is not None
            )
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


def _planned_repositories(runs_root: Path) -> set[str]:
    planned: set[str] = set()
    if not runs_root.is_dir() or runs_root.is_symlink():
        return planned
    for state_path in runs_root.glob("*/state.json"):
        try:
            job = json.loads(
                (state_path.parent / "job.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            continue
        repository = str((job.get("source") or {}).get("repository") or "")
        if repository:
            planned.add(repository.casefold())
    return planned


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


def _language_is_enabled(language: str, enabled_languages: list[str]) -> bool:
    enabled = {
        str(value).strip().casefold()
        for value in enabled_languages
        if str(value).strip()
    }
    return not enabled or str(language).strip().casefold() in enabled
