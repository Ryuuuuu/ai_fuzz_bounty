#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This bootstrap must run on Ubuntu Linux or WSL2." >&2
  exit 1
fi

for command in python3 git; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Missing required command: $command" >&2
    exit 1
  fi
done

python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or newer is required")
PY

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

if [[ "${1:-}" != "--check-only" ]]; then
  if ! python3 -m venv .venv; then
    echo "Could not create .venv. On Ubuntu, install the python3-venv package." >&2
    exit 1
  fi
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/python -m pip install -e .
  if [[ ! -f config.toml ]]; then
    cp config.example.toml config.toml
  fi
fi

missing=0
for command in docker codex; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Optional runtime command is not ready: $command" >&2
    missing=1
  fi
done

python_bin="$project_root/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
  python_bin=python3
fi
"$python_bin" -m unittest discover -s tests -q

if [[ -x "$project_root/.venv/bin/fts" ]]; then
  "$project_root/.venv/bin/fts" doctor
  "$project_root/.venv/bin/fuzz-pipeline" doctor
fi

if [[ "$missing" -ne 0 ]]; then
  echo "Project checks passed; install the missing runtime commands before fuzzing." >&2
  exit 2
fi

echo "Ubuntu setup checks passed."
