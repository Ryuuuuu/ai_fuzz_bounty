from __future__ import annotations

from datetime import datetime, timezone

from .models import AIAssessment, RepoSnapshot, StaticAssessment


BINARY_LANGUAGES = {"C", "C++", "Rust", "Go"}
BUILD_FILES = {
    "cargo.toml",
    "cmakelists.txt",
    "meson.build",
    "configure.ac",
    "configure",
    "makefile",
    "go.mod",
}
SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".go")


def assess_static(repo: RepoSnapshot) -> StaticAssessment:
    paths = [path.casefold() for path in repo.paths]
    root_names = {path for path in paths if "/" not in path}
    text = f"{repo.description}\n{repo.readme_excerpt}".casefold()
    signals: list[str] = []
    blockers: list[str] = []
    score = 0

    source_count = sum(path.endswith(SOURCE_SUFFIXES) for path in paths)
    if repo.language in BINARY_LANGUAGES:
        score += 18
        signals.append(f"native_or_compiled_language:{repo.language}")
    elif repo.language:
        blockers.append(f"non_primary_binary_language:{repo.language}")

    build_hits = sorted(root_names & BUILD_FILES)
    if build_hits:
        score += 12
        signals.append(f"standard_build:{','.join(build_hits[:3])}")
    else:
        blockers.append("no_root_build_file")

    fuzz_paths = [
        path
        for path in paths
        if path.startswith(("fuzz/", "fuzzing/", "tests/fuzz/", "test/fuzz/"))
        or "/fuzz/" in path
        or "oss-fuzz" in path
        or "cifuzz" in path
    ]
    if fuzz_paths:
        score += 28
        signals.append(f"existing_fuzz_assets:{len(fuzz_paths)}")
    else:
        blockers.append("no_existing_fuzz_assets")

    if any(
        path.startswith(("test/", "tests/", "testing/")) or "/tests/" in path
        for path in paths
    ):
        score += 10
        signals.append("test_suite")

    linux_signals = (
        "linux" in text
        or "ubuntu" in text
        or "debian" in text
        or any("dockerfile" in path or "linux" in path for path in paths)
    )
    if linux_signals:
        score += 8
        signals.append("linux_evidence")
    else:
        blockers.append("linux_support_not_explicit")

    local_shape = any(
        token in text
        for token in ("command line", "command-line", "cli", "library", "parser", "decoder")
    )
    if local_shape:
        score += 8
        signals.append("local_entry_shape")

    if _recently_pushed(repo.pushed_at, days=365):
        score += 8
        signals.append("recent_activity")
    else:
        blockers.append("not_recently_pushed")

    if 0 < repo.size_kb <= 100_000:
        score += 8
        signals.append("moderate_repository_size")
    elif repo.size_kb > 300_000:
        score -= 8
        blockers.append("very_large_repository")

    if source_count == 0:
        blockers.append("no_compiled_source_seen")
    elif source_count < 250:
        score += 5
        signals.append("compact_source_tree")

    difficulty = 3
    if fuzz_paths:
        difficulty -= 1
    if build_hits and repo.size_kb <= 100_000:
        difficulty -= 1
    if repo.size_kb > 300_000:
        difficulty += 1
    if any(
        token in text
        for token in ("kubernetes", "cluster", "cloud service", "database server", "monorepo")
    ):
        difficulty += 1
        blockers.append("external_or_distributed_runtime")
    if len(paths) >= 4500:
        difficulty += 1
        blockers.append("large_tree_or_tree_truncated")
    difficulty = max(1, min(5, difficulty))

    if fuzz_paths:
        entry_kind = "existing_harness"
    elif any(token in text for token in ("parser", "decoder", "deserialize", "file format")):
        entry_kind = "parser_or_decoder"
    elif any(token in text for token in ("command line", "command-line", " cli ")):
        entry_kind = "command_line"
    elif "library" in text:
        entry_kind = "library_api"
    else:
        entry_kind = "manual_review"

    return StaticAssessment(
        fuzz_score=max(0, min(100, score)),
        reproduce_difficulty=difficulty,
        signals=signals,
        blockers=blockers,
        suggested_entry_kind=entry_kind,
    )


def final_score(static: StaticAssessment, ai: AIAssessment | None = None) -> int:
    if ai:
        fuzz_score = round(static.fuzz_score * 0.4 + ai.fuzz_score * 0.6)
        difficulty = round(
            static.reproduce_difficulty * 0.4 + ai.reproduce_difficulty * 0.6
        )
    else:
        fuzz_score = static.fuzz_score
        difficulty = static.reproduce_difficulty
    ease_score = (6 - max(1, min(5, difficulty))) * 20
    return max(0, min(100, round(fuzz_score * 0.7 + ease_score * 0.3)))


def _recently_pushed(value: str, days: int) -> bool:
    if not value:
        return False
    try:
        pushed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    now = datetime.now(timezone.utc)
    return 0 <= (now - pushed).days <= days
