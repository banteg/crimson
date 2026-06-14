#!/bin/sh
# Run an original-era MSVC cl.exe under Wine.
# Compiler is selected by MSVC_VER (default msvc6.5).
set -eu

MATCH_ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$MATCH_ROOT/../.." && pwd)"
MSVC_VER="${MSVC_VER:-msvc6.5}"

find_compiler() {
    if [ -n "${CRIMSON_MSVC_ROOT:-}" ]; then
        if [ -f "$CRIMSON_MSVC_ROOT/Bin/CL.EXE" ] || [ -f "$CRIMSON_MSVC_ROOT/Bin/cl.exe" ]; then
            printf '%s\n' "$CRIMSON_MSVC_ROOT"
            return 0
        fi
        if [ -f "$CRIMSON_MSVC_ROOT/$MSVC_VER/Bin/CL.EXE" ] || [ -f "$CRIMSON_MSVC_ROOT/$MSVC_VER/Bin/cl.exe" ]; then
            printf '%s\n' "$CRIMSON_MSVC_ROOT/$MSVC_VER"
            return 0
        fi
    fi
    if [ -f "$MATCH_ROOT/compilers/$MSVC_VER/Bin/CL.EXE" ] || [ -f "$MATCH_ROOT/compilers/$MSVC_VER/Bin/cl.exe" ]; then
        printf '%s\n' "$MATCH_ROOT/compilers/$MSVC_VER"
        return 0
    fi
    if [ -f "$REPO_ROOT/../snail-mail/tools/match/compilers/$MSVC_VER/Bin/CL.EXE" ] || [ -f "$REPO_ROOT/../snail-mail/tools/match/compilers/$MSVC_VER/Bin/cl.exe" ]; then
        printf '%s\n' "$REPO_ROOT/../snail-mail/tools/match/compilers/$MSVC_VER"
        return 0
    fi
    return 1
}

MSVC_ROOT="$(find_compiler || true)"
if [ -z "$MSVC_ROOT" ]; then
    echo "error: could not find $MSVC_VER/Bin/cl.exe" >&2
    echo "set CRIMSON_MSVC_ROOT or unpack it under tools/match/compilers/$MSVC_VER" >&2
    exit 1
fi

WINE="${WINE:-/Applications/Wine Stable.app/Contents/Resources/wine/bin/wine}"
export WINEPREFIX="${WINEPREFIX:-$HOME/.wine-crimson}"
export WINEDEBUG="${WINEDEBUG:--all}"
export MVK_CONFIG_LOG_LEVEL="${MVK_CONFIG_LOG_LEVEL:-0}"

INCLUDE="Z:$(echo "$MSVC_ROOT/Include" | tr '/' '\\')"
INCLUDE="$INCLUDE;Z:$(echo "$MATCH_ROOT/include" | tr '/' '\\')"
INCLUDE="$INCLUDE;Z:$(echo "$REPO_ROOT/third_party/headers" | tr '/' '\\')"
export INCLUDE

CL_EXE="$MSVC_ROOT/Bin/CL.EXE"
[ -f "$CL_EXE" ] || CL_EXE="$MSVC_ROOT/Bin/cl.exe"

exec "$WINE" "$CL_EXE" /nologo "$@"
