#!/usr/bin/env bash
# Parity test runner for the standalone hermes-ci-triage plugin repo.
#
# Mirrors the hermes-agent CI environment for deterministic, credential-free
# runs: TZ=UTC, LANG=C.UTF-8, PYTHONHASHSEED=0, and common CI/cloud credential
# vars blanked so nothing leaks into a test. Uses the hermes-agent venv if one
# is found (so `hermes_cli` / `tools` import), else the ambient python.
#
# Usage:  ./run_tests.sh                # whole suite
#         ./run_tests.sh tests/test_patterns.py -- -v
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY="python"
for candidate in \
  "$REPO_ROOT/.venv/bin/python" \
  "$REPO_ROOT/../hermes-agent/.venv/bin/python" \
  "$HOME/.hermes/hermes-agent/venv/bin/python"; do
  if [ -x "$candidate" ]; then PY="$candidate"; break; fi
done

# Split args at a literal '--' into pytest paths and pytest passthrough args.
PATHS=()
PASSTHRU=()
seen_dd=0
for arg in "$@"; do
  if [ "$arg" = "--" ]; then seen_dd=1; continue; fi
  if [ "$seen_dd" -eq 1 ]; then PASSTHRU+=("$arg"); else PATHS+=("$arg"); fi
done
if [ "${#PATHS[@]}" -eq 0 ]; then PATHS=("tests/"); fi

exec env \
  -u GITHUB_TOKEN -u GITLAB_TOKEN -u JENKINS_TOKEN \
  -u OPENROUTER_API_KEY -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u CI \
  TZ=UTC LANG=C.UTF-8 PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 \
  "$PY" -m pytest "${PATHS[@]}" "${PASSTHRU[@]}"
