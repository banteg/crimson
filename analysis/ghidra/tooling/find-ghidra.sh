#!/bin/bash
# Locate Ghidra's analyzeHeadless script (macOS + Linux friendly)

set -euo pipefail

if [[ -n "${GHIDRA_HEADLESS:-}" ]]; then
    if [[ -x "$GHIDRA_HEADLESS" ]]; then
        echo "$GHIDRA_HEADLESS"
        exit 0
    fi
    echo "ERROR: GHIDRA_HEADLESS is set but not executable: $GHIDRA_HEADLESS" >&2
    exit 1
fi

if [[ -n "${GHIDRA_HOME:-}" ]]; then
    CANDIDATE="$GHIDRA_HOME/support/analyzeHeadless"
    if [[ -x "$CANDIDATE" ]]; then
        echo "$CANDIDATE"
        exit 0
    fi
fi

if command -v analyzeHeadless >/dev/null 2>&1; then
    CANDIDATE="$(command -v analyzeHeadless)"
    if [[ -x "$CANDIDATE" ]]; then
        echo "$CANDIDATE"
        exit 0
    fi
fi

shopt -s nullglob
for CANDIDATE in /opt/ghidra*/support/analyzeHeadless; do
    if [[ -x "$CANDIDATE" ]]; then
        echo "$CANDIDATE"
        exit 0
    fi
done
shopt -u nullglob

HEADLESS_CANDIDATES=(
    "/opt/ghidra/support/analyzeHeadless"
    "/usr/local/ghidra/support/analyzeHeadless"
    "/usr/share/ghidra/support/analyzeHeadless"
    "/Applications/Ghidra.app/Contents/Resources/ghidra/support/analyzeHeadless"
)

for CANDIDATE in "${HEADLESS_CANDIDATES[@]}"; do
    if [[ -x "$CANDIDATE" ]]; then
        echo "$CANDIDATE"
        exit 0
    fi
done

echo "ERROR: Could not find Ghidra analyzeHeadless." >&2
echo "Tried GHIDRA_HEADLESS, GHIDRA_HOME, PATH, and common install locations." >&2
exit 1
