#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


FIELD = re.compile(r"(?m)^(main_repo|language):\s*['\"]?([^'\"\s#]+)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("oss_fuzz", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.oss_fuzz.resolve()
    commit = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    projects = []
    for metadata in sorted((root / "projects").glob("*/project.yaml")):
        fields = dict(FIELD.findall(metadata.read_text(encoding="utf-8", errors="replace")))
        repository = normalize_repository(fields.get("main_repo", ""))
        if repository:
            projects.append(
                {
                    "project": metadata.parent.name,
                    "repository": repository,
                    "language": fields.get("language", ""),
                }
            )
    payload = {
        "schema_version": 1,
        "oss_fuzz_commit": commit,
        "project_count": len(projects),
        "projects": projects,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def normalize_repository(url: str) -> str:
    match = re.fullmatch(
        r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?",
        url,
        re.IGNORECASE,
    )
    return match.group(1).casefold() if match else ""


if __name__ == "__main__":
    main()
