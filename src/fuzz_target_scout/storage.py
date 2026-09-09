from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import AIAssessment, Candidate


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self._migrate()

    def close(self) -> None:
        self.connection.close()

    def _migrate(self) -> None:
        self.connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 0,
                verified_count INTEGER NOT NULL DEFAULT 0,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS candidates (
                full_name TEXT PRIMARY KEY,
                repo_url TEXT NOT NULL,
                default_branch TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                language TEXT NOT NULL,
                stars INTEGER NOT NULL,
                policy_status TEXT NOT NULL,
                policy_confidence INTEGER NOT NULL,
                policy_source TEXT NOT NULL,
                program_url TEXT NOT NULL,
                security_url TEXT NOT NULL,
                fuzz_score INTEGER NOT NULL,
                reproduce_difficulty INTEGER NOT NULL,
                final_score INTEGER NOT NULL,
                ai_used INTEGER NOT NULL,
                suggested_entry_kind TEXT NOT NULL,
                details_json TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                last_scan_id INTEGER,
                FOREIGN KEY(last_scan_id) REFERENCES scans(id)
            );
            CREATE INDEX IF NOT EXISTS idx_candidates_queue
              ON candidates(policy_status, final_score DESC);
            CREATE TABLE IF NOT EXISTS ai_cache (
                cache_key TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                model TEXT NOT NULL,
                prompt_version TEXT NOT NULL,
                response_json TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                cached_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        self.connection.commit()

    def start_scan(self, source: str) -> int:
        cursor = self.connection.execute(
            "INSERT INTO scans(started_at, source, status) VALUES (?, ?, 'running')",
            (utc_now(), source),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def finish_scan(
        self,
        scan_id: int,
        status: str,
        seen_count: int,
        verified_count: int,
        error: str = "",
    ) -> None:
        self.connection.execute(
            """
            UPDATE scans
               SET completed_at=?, status=?, seen_count=?, verified_count=?, error=?
             WHERE id=?
            """,
            (utc_now(), status, seen_count, verified_count, error or None, scan_id),
        )
        self.connection.commit()

    def upsert_candidate(self, candidate: Candidate, scan_id: int) -> None:
        now = utc_now()
        details = _candidate_details(candidate)
        entry_kind = (
            candidate.ai.suggested_entry_kind
            if candidate.ai
            else candidate.static.suggested_entry_kind
        )
        self.connection.execute(
            """
            INSERT INTO candidates(
                full_name, repo_url, default_branch, head_sha, language, stars,
                policy_status, policy_confidence, policy_source, program_url,
                security_url, fuzz_score, reproduce_difficulty, final_score,
                ai_used, suggested_entry_kind, details_json, first_seen_at,
                last_seen_at, last_scan_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(full_name) DO UPDATE SET
                repo_url=excluded.repo_url,
                default_branch=excluded.default_branch,
                head_sha=excluded.head_sha,
                language=excluded.language,
                stars=excluded.stars,
                policy_status=excluded.policy_status,
                policy_confidence=excluded.policy_confidence,
                policy_source=excluded.policy_source,
                program_url=excluded.program_url,
                security_url=excluded.security_url,
                fuzz_score=excluded.fuzz_score,
                reproduce_difficulty=excluded.reproduce_difficulty,
                final_score=excluded.final_score,
                ai_used=excluded.ai_used,
                suggested_entry_kind=excluded.suggested_entry_kind,
                details_json=excluded.details_json,
                last_seen_at=excluded.last_seen_at,
                last_scan_id=excluded.last_scan_id
            """,
            (
                candidate.repo.full_name,
                candidate.repo.html_url,
                candidate.repo.default_branch,
                candidate.repo.head_sha,
                candidate.repo.language,
                candidate.repo.stars,
                candidate.policy.status,
                candidate.policy.confidence,
                candidate.policy.source,
                candidate.policy.program_url,
                candidate.repo.security_url,
                candidate.static.fuzz_score,
                candidate.static.reproduce_difficulty,
                candidate.final_score,
                int(candidate.ai is not None),
                entry_kind,
                json.dumps(details, ensure_ascii=False, separators=(",", ":")),
                now,
                now,
                scan_id,
            ),
        )
        self.connection.commit()

    def get_ai_cache(self, cache_key: str) -> AIAssessment | None:
        row = self.connection.execute(
            "SELECT response_json FROM ai_cache WHERE cache_key=?", (cache_key,)
        ).fetchone()
        if not row:
            return None
        data = json.loads(row["response_json"])
        return AIAssessment(**data)

    def put_ai_cache(
        self,
        cache_key: str,
        full_name: str,
        head_sha: str,
        model: str,
        prompt_version: str,
        assessment: AIAssessment,
        usage: dict[str, int],
    ) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO ai_cache(
                cache_key, full_name, head_sha, model, prompt_version,
                response_json, input_tokens, cached_tokens, output_tokens, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cache_key,
                full_name,
                head_sha,
                model,
                prompt_version,
                json.dumps(assessment.to_dict(), ensure_ascii=False),
                usage.get("input_tokens", 0),
                usage.get("cached_tokens", 0),
                usage.get("output_tokens", 0),
                utc_now(),
            ),
        )
        self.connection.commit()

    def list_candidates(
        self, limit: int = 50, include_all: bool = False
    ) -> list[sqlite3.Row]:
        where = "" if include_all else "WHERE policy_status IN ('verified','conditional')"
        return list(
            self.connection.execute(
                f"""
                SELECT full_name, language, stars, policy_status, fuzz_score,
                       reproduce_difficulty, final_score, ai_used, program_url,
                       security_url, repo_url, head_sha, default_branch,
                       suggested_entry_kind, details_json
                  FROM candidates
                  {where}
                 ORDER BY CASE policy_status WHEN 'verified' THEN 0 ELSE 1 END,
                          final_score DESC, full_name
                 LIMIT ?
                """,
                (limit,),
            )
        )

    def export_rows(
        self,
        minimum_score: int,
        include_conditional: bool,
    ) -> Iterable[dict[str, Any]]:
        statuses = ("verified", "conditional") if include_conditional else ("verified",)
        placeholders = ",".join("?" for _ in statuses)
        rows = self.connection.execute(
            f"""
            SELECT *
              FROM candidates
             WHERE policy_status IN ({placeholders}) AND final_score >= ?
             ORDER BY final_score DESC, full_name
            """,
            (*statuses, minimum_score),
        )
        for row in rows:
            details = json.loads(row["details_json"])
            yield {
                "schema_version": 1,
                "repository": row["full_name"],
                "repository_url": row["repo_url"],
                "commit": row["head_sha"],
                "default_branch": row["default_branch"],
                "language": row["language"],
                "policy": {
                    "status": row["policy_status"],
                    "confidence": row["policy_confidence"],
                    "source": row["policy_source"],
                    "program_url": row["program_url"],
                    "security_url": row["security_url"],
                    "note": details["policy_note"],
                },
                "assessment": {
                    "fuzz_score": row["fuzz_score"],
                    "reproduce_difficulty": row["reproduce_difficulty"],
                    "final_score": row["final_score"],
                    "ai_used": bool(row["ai_used"]),
                    "suggested_entry_kind": row["suggested_entry_kind"],
                    "signals": details["signals"],
                    "blockers": details["blockers"],
                    "ai": details.get("ai"),
                },
                "observed_at": row["last_seen_at"],
            }


def make_ai_cache_key(
    full_name: str,
    head_sha: str,
    model: str,
    prompt_version: str,
    evidence_digest: str,
) -> str:
    raw = "\0".join((full_name, head_sha, model, prompt_version, evidence_digest))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _candidate_details(candidate: Candidate) -> dict[str, Any]:
    security_digest = hashlib.sha256(
        candidate.repo.security_text.encode("utf-8")
    ).hexdigest()
    return {
        "description": candidate.repo.description,
        "size_kb": candidate.repo.size_kb,
        "license": candidate.repo.license_name,
        "topics": candidate.repo.topics,
        "pushed_at": candidate.repo.pushed_at,
        "path_count_seen": len(candidate.repo.paths),
        "interesting_paths": [
            path
            for path in candidate.repo.paths
            if any(marker in path.casefold() for marker in ("fuzz", "test", "cargo", "cmake"))
        ][:50],
        "security_sha256": security_digest,
        "policy_note": candidate.policy.note,
        "signals": candidate.static.signals,
        "blockers": candidate.static.blockers,
        "ai": candidate.ai.to_dict() if candidate.ai else None,
    }
