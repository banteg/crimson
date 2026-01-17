#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_FILE="${ROOT_DIR}/plan.md"
PROGRESS_FILE="${ROOT_DIR}/plan_progress.log"

CODEX_BIN=${CODEX_BIN:-codex}
CODEX_SUBCMD=${CODEX_SUBCMD:-exec}
CODEX_ARGS=${CODEX_ARGS:-}

read -r -a CODEX_ARGS_ARR <<< "${CODEX_ARGS}"

mkdir -p "${ROOT_DIR}"
touch "${PROGRESS_FILE}"

for i in $(seq 1 20); do
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "=== Iteration ${i}/20 @ ${ts} ==="

  {
    cat "${PLAN_FILE}"
    echo
    echo "RUN: ${i}/20"
    echo "UTC: ${ts}"
    echo "PROGRESS (last 5):"
    tail -n 5 "${PROGRESS_FILE}" || true
    echo
    echo "Reminder: append one line to plan_progress.log this run."
  } | "${CODEX_BIN}" "${CODEX_SUBCMD}" "${CODEX_ARGS_ARR[@]}"

done
