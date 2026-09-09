from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import PolicyAssessment, RepoSnapshot


TRUSTED_PROGRAM_DOMAINS = {
    "hackerone.com",
    "www.hackerone.com",
    "bugcrowd.com",
    "www.bugcrowd.com",
    "yeswehack.com",
    "www.yeswehack.com",
    "intigriti.com",
    "app.intigriti.com",
    "microsoft.com",
    "www.microsoft.com",
}

STRONG_BOUNTY_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bpublic bug bounty\b",
        r"\bbug bounty program\b",
        r"\beligible for (?:a )?bounty(?: reward)?\b",
        r"\bbounty rewards?\b",
        r"\bmight fetch a bounty\b",
        r"\breceive (?:a )?bounty\b",
        r"\bactive bug bounty\b",
    )
]

NEGATIVE_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bdo not offer (?:monetary )?bounties\b",
        r"\bno (?:monetary )?(?:bug )?bount(?:y|ies)\b",
        r"\bnot eligible for (?:a )?bounty\b",
        r"\bdo not provide (?:a )?(?:financial|monetary) reward\b",
    )
]

URL_RE = re.compile(r"https://[^\s)>\"']+", re.IGNORECASE)


class PolicyVerifier:
    def __init__(self, catalog_path: str | Path, max_age_days: int = 45):
        self.catalog_path = Path(catalog_path)
        self.max_age_days = max_age_days
        self.entries = self._load_catalog()

    def _load_catalog(self) -> dict[str, dict[str, Any]]:
        if not self.catalog_path.exists():
            return {}
        with self.catalog_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return {
            entry["full_name"].casefold(): entry
            for entry in payload.get("entries", [])
            if entry.get("full_name")
        }

    @property
    def catalog_names(self) -> list[str]:
        return [entry["full_name"] for entry in self.entries.values()]

    def verify(self, repo: RepoSnapshot, today: date | None = None) -> PolicyAssessment:
        if repo.archived or repo.disabled:
            return PolicyAssessment(
                status="rejected",
                confidence=100,
                source="github",
                note="Repository is archived or disabled.",
            )

        entry = self.entries.get(repo.full_name.casefold())
        if entry:
            return self._from_catalog(repo, entry, today or date.today())
        return self._from_security_file(repo)

    def _from_catalog(
        self, repo: RepoSnapshot, entry: dict[str, Any], today: date
    ) -> PolicyAssessment:
        current_text = repo.security_text
        has_strong_current_claim = any(
            pattern.search(current_text) for pattern in STRONG_BOUNTY_PATTERNS
        )
        has_current_rejection = any(
            pattern.search(current_text) for pattern in NEGATIVE_PATTERNS
        )
        if has_current_rejection and not has_strong_current_claim:
            return PolicyAssessment(
                status="rejected",
                confidence=100,
                source="security.md",
                note="The current repository policy explicitly says reports are not paid.",
            )
        try:
            verified_on = date.fromisoformat(entry["last_verified"])
            age = (today - verified_on).days
        except (KeyError, TypeError, ValueError):
            age = self.max_age_days + 1

        if not repo.security_text.strip():
            return PolicyAssessment(
                status="needs_review",
                confidence=35,
                source="catalog",
                program_url=entry.get("program_url", ""),
                note="Catalog entry exists, but the repository security policy could not be read.",
            )
        if age < 0 or age > self.max_age_days:
            current = self._from_security_file(repo)
            if current.status == "verified":
                current.note = (
                    "Catalog entry is stale, but the current repository policy "
                    "independently and explicitly confirms bounty eligibility."
                )
                return current
            return PolicyAssessment(
                status="needs_review",
                confidence=45,
                source="catalog",
                program_url=entry.get("program_url", ""),
                note=f"Catalog verification is stale ({age} days old).",
            )

        status = entry.get("status", "needs_review")
        if status not in {"verified", "conditional"}:
            status = "needs_review"
        return PolicyAssessment(
            status=status,
            confidence=100 if status == "verified" else 90,
            source="catalog",
            program_url=entry.get("program_url", ""),
            note=entry.get("scope_note", ""),
        )

    def _from_security_file(self, repo: RepoSnapshot) -> PolicyAssessment:
        text = repo.security_text.strip()
        if not text:
            return PolicyAssessment(
                status="rejected",
                confidence=95,
                source="security.md",
                note="No readable SECURITY.md was found.",
            )

        urls = [url.rstrip("].,") for url in URL_RE.findall(text)]
        trusted_urls = [
            url
            for url in urls
            if (urlparse(url).hostname or "").casefold() in TRUSTED_PROGRAM_DOMAINS
        ]
        strong = any(pattern.search(text) for pattern in STRONG_BOUNTY_PATTERNS)
        negative = any(pattern.search(text) for pattern in NEGATIVE_PATTERNS)

        if strong and trusted_urls:
            return PolicyAssessment(
                status="verified",
                confidence=85,
                source="security.md",
                program_url=trusted_urls[0],
                note="Repository policy explicitly describes bounty eligibility and links a trusted platform.",
            )
        if negative and not strong:
            return PolicyAssessment(
                status="rejected",
                confidence=95,
                source="security.md",
                program_url=trusted_urls[0] if trusted_urls else "",
                note="Repository policy explicitly says reports are not paid.",
            )
        if trusted_urls:
            return PolicyAssessment(
                status="needs_review",
                confidence=55,
                source="security.md",
                program_url=trusted_urls[0],
                note="A bounty platform is linked, but exact paid scope is not explicit.",
            )
        return PolicyAssessment(
            status="rejected",
            confidence=85,
            source="security.md",
            note="No explicit paid bug-bounty evidence was found.",
        )
