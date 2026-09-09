#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

from fuzz_target_scout.generic_integration import create_generic_project


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a tiny project through generated OSS-Fuzz integration"
    )
    parser.add_argument("--oss-fuzz", default=".tools/oss-fuzz")
    args = parser.parse_args()
    oss_fuzz = Path(args.oss_fuzz).resolve()
    if not (oss_fuzz / "infra" / "helper.py").is_file():
        raise SystemExit(f"OSS-Fuzz checkout not found: {oss_fuzz}")
    environment = os.environ.copy()
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "CODEX_API_KEY"):
        environment.pop(name, None)
    with tempfile.TemporaryDirectory(
        prefix="fts-generic-integration-", ignore_cleanup_errors=True
    ) as directory:
        root = Path(directory)
        worktree = root / "oss-fuzz"
        source = root / "source"
        job = root / "job"
        (job / "artifacts").mkdir(parents=True)
        source.mkdir()
        project = "fts-generic-smoke"
        subprocess.run(
            [
                "git", "-C", str(oss_fuzz), "worktree", "add", "--detach",
                str(worktree), "HEAD",
            ],
            check=True,
            env=environment,
        )
        try:
            (source / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.16)\n"
                "project(fts_smoke LANGUAGES CXX)\n"
                "add_library(parser STATIC parser.cc)\n",
                encoding="utf-8",
            )
            (source / "parser.h").write_text(
                "#pragma once\n#include <cstddef>\n"
                "int parse_bytes(const unsigned char*, std::size_t);\n",
                encoding="utf-8",
            )
            (source / "parser.cc").write_text(
                '#include "parser.h"\nint parse_bytes(const unsigned char* p, std::size_t n) '
                "{ return n > 3 && p[0] == 'F' && p[1] == 'T' && p[2] == 'S'; }\n",
                encoding="utf-8",
            )
            (source / "fuzz.cc").write_text(
                '#include "parser.h"\n#include <cstddef>\n#include <cstdint>\n'
                'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) '
                "{ parse_bytes(data, size); return 0; }\n",
                encoding="utf-8",
            )
            create_generic_project(
                job_dir=job,
                source=source,
                project_dir=worktree / "projects" / project,
                project_name=project,
                pipeline={},
            )
            helper = worktree / "infra" / "helper.py"
            subprocess.run(
                [
                    "python3", str(helper), "build_image", "--no-pull", "--cache",
                    project,
                ],
                check=True,
                env=environment,
            )
            subprocess.run(
                [
                    "python3", str(helper), "build_fuzzers", "--clean", "--sanitizer",
                    "address", project, str(source),
                ],
                check=True,
                env=environment,
            )
            binary = worktree / "build" / "out" / project / "generic_fuzzer"
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise SystemExit("generated integration produced no executable fuzzer")
            print(binary)
        finally:
            build_root = worktree / "build"
            if build_root.is_dir():
                subprocess.run(
                    [
                        "docker", "run", "--rm", "-v", f"{build_root}:/cleanup",
                        f"gcr.io/oss-fuzz/{project}", "bash", "-lc",
                        f"rm -rf /cleanup/out/{project} /cleanup/work/{project}",
                    ],
                    check=False,
                    env=environment,
                )
            subprocess.run(
                [
                    "git", "-C", str(oss_fuzz), "worktree", "remove", "--force",
                    str(worktree),
                ],
                check=False,
                env=environment,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
