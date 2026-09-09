from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import replace
from typing import Any

from .models import RepoSnapshot


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    def __init__(self, config: dict[str, Any]):
        self.api_url = str(config["api_url"]).rstrip("/")
        self.timeout = int(config["timeout_seconds"])
        self.max_tree_paths = int(config["max_tree_paths"])
        self.max_architecture_files = int(config.get("max_architecture_files", 8))
        self.token = os.environ.get("GITHUB_TOKEN", "").strip()
        self.rate_remaining: int | None = None
        self.rate_reset: str | None = None

    def _request(self, path_or_url: str) -> Any:
        url = (
            path_or_url
            if path_or_url.startswith("https://")
            else f"{self.api_url}/{path_or_url.lstrip('/')}"
        )
        if not url.startswith(f"{self.api_url}/"):
            raise GitHubError(f"Refusing non-GitHub API URL: {url}")
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "fuzz-target-scout/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                remaining = response.headers.get("X-RateLimit-Remaining")
                self.rate_remaining = int(remaining) if remaining else self.rate_remaining
                self.rate_reset = response.headers.get("X-RateLimit-Reset")
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read(1000).decode("utf-8", errors="replace")
            if exc.code == 404:
                return None
            raise GitHubError(f"GitHub API {exc.code} for {url}: {body}") from exc
        except urllib.error.URLError as exc:
            raise GitHubError(f"GitHub request failed for {url}: {exc.reason}") from exc

    @staticmethod
    def _snapshot(item: dict[str, Any]) -> RepoSnapshot:
        license_data = item.get("license") or {}
        return RepoSnapshot(
            full_name=item["full_name"],
            html_url=item.get("html_url", f"https://github.com/{item['full_name']}"),
            default_branch=item.get("default_branch", "main"),
            head_sha="",
            description=item.get("description") or "",
            language=item.get("language") or "",
            stars=int(item.get("stargazers_count", 0)),
            forks=int(item.get("forks_count", 0)),
            size_kb=int(item.get("size", 0)),
            archived=bool(item.get("archived", False)),
            disabled=bool(item.get("disabled", False)),
            pushed_at=item.get("pushed_at") or "",
            license_name=license_data.get("spdx_id") or license_data.get("name") or "",
            topics=list(item.get("topics") or []),
        )

    def search_repositories(self, query: str, limit: int) -> list[RepoSnapshot]:
        results: list[RepoSnapshot] = []
        page = 1
        while len(results) < limit:
            per_page = min(100, limit - len(results))
            params = urllib.parse.urlencode(
                {
                    "q": query,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": per_page,
                    "page": page,
                }
            )
            payload = self._request(f"/search/repositories?{params}") or {}
            items = payload.get("items") or []
            results.extend(self._snapshot(item) for item in items)
            if len(items) < per_page:
                break
            page += 1
        return results[:limit]

    def get_repository(self, full_name: str) -> RepoSnapshot | None:
        encoded = "/".join(urllib.parse.quote(part, safe="") for part in full_name.split("/", 1))
        payload = self._request(f"/repos/{encoded}")
        return self._snapshot(payload) if payload else None

    def load_security_policy(self, repo: RepoSnapshot) -> RepoSnapshot:
        encoded = "/".join(
            urllib.parse.quote(part, safe="") for part in repo.full_name.split("/", 1)
        )
        profile = self._request(f"/repos/{encoded}/community/profile") or {}
        policy = ((profile.get("files") or {}).get("security") or {})
        api_url = policy.get("url") or ""
        html_url = policy.get("html_url") or f"{repo.html_url}/security/policy"
        content = self._request(api_url) if api_url else None
        if not content:
            for path in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
                quoted_path = urllib.parse.quote(path, safe="/")
                ref = urllib.parse.quote(repo.default_branch, safe="")
                content = self._request(
                    f"/repos/{encoded}/contents/{quoted_path}?ref={ref}"
                )
                if content:
                    html_url = content.get("html_url") or html_url
                    break
        if not content:
            return replace(repo, security_url="")
        return replace(
            repo,
            security_url=html_url,
            security_text=self._decode_content(content),
        )

    def hydrate_code_evidence(self, repo: RepoSnapshot) -> RepoSnapshot:
        encoded = "/".join(
            urllib.parse.quote(part, safe="") for part in repo.full_name.split("/", 1)
        )
        branch = urllib.parse.quote(repo.default_branch, safe="")
        tree = self._request(f"/repos/{encoded}/git/trees/{branch}?recursive=1") or {}
        blobs = [
            item
            for item in (tree.get("tree") or [])
            if item.get("type") == "blob" and isinstance(item.get("path"), str)
        ][: self.max_tree_paths]
        paths = [str(item["path"]) for item in blobs]
        readme = self._request(f"/repos/{encoded}/readme")
        architecture_files: dict[str, str] = {}
        for item in self._architecture_blobs(blobs):
            payload = self._request(f"/repos/{encoded}/git/blobs/{item['sha']}") or {}
            content = self._decode_content(payload)
            if content:
                architecture_files[str(item["path"])] = content[:32_000]
        return replace(
            repo,
            head_sha=tree.get("sha") or repo.head_sha,
            paths=paths,
            readme_excerpt=self._compact_readme(self._decode_content(readme)),
            architecture_files=architecture_files,
        )

    def _architecture_blobs(self, blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        arch = re.compile(r"(?i)(?:aarch64|arm64|armv8|amd64|x86[_-]?64)")
        build_or_ci = re.compile(
            r"(?i)(?:^|/)(?:\.github/workflows|ci|scripts|docs?)/|"
            r"(?:dockerfile|docker-bake|azure-pipelines|cmakepresets|build)"
        )
        candidates = []
        for item in blobs:
            path = str(item.get("path") or "")
            size = int(item.get("size") or 0)
            sha = str(item.get("sha") or "")
            if not sha or size > 256_000:
                continue
            if arch.search(path) or build_or_ci.search(path):
                candidates.append(item)
        candidates.sort(
            key=lambda item: (
                not bool(arch.search(str(item.get("path") or ""))),
                not str(item.get("path") or "").startswith(".github/workflows/"),
                str(item.get("path") or "").casefold(),
            )
        )
        return candidates[: self.max_architecture_files]

    @staticmethod
    def _decode_content(payload: dict[str, Any] | None) -> str:
        if not payload:
            return ""
        content = payload.get("content") or ""
        if payload.get("encoding") == "base64":
            try:
                return base64.b64decode(content).decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                return ""
        return str(content)

    @staticmethod
    def _compact_readme(text: str, max_chars: int = 5000) -> str:
        if not text:
            return ""
        keywords = re.compile(
            r"(?i)(linux|ubuntu|debian|build|compile|test|fuzz|docker|cmake|cargo|"
            r"standalone|command.line|library|dependencies|requirements|arm64|"
            r"aarch64|amd64|x86.64)"
        )
        selected = [text[:1200]]
        for line in text.splitlines():
            if keywords.search(line):
                selected.append(line[:500])
            if sum(map(len, selected)) >= max_chars:
                break
        return "\n".join(selected)[:max_chars]
