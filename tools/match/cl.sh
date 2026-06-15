#!/bin/sh
# Run an original-era MSVC cl.exe under wibo.
# Compiler is selected by MSVC_VER (default msvc6.5).
set -eu

MATCH_ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$MATCH_ROOT/../.." && pwd)"
MSVC_VER="${MSVC_VER:-msvc6.5}"
WIBO="${WIBO:-}"

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

if [ -z "$WIBO" ]; then
    if [ -x "$MATCH_ROOT/bin/wibo" ]; then
        WIBO="$MATCH_ROOT/bin/wibo"
    elif command -v wibo >/dev/null 2>&1; then
        WIBO="wibo"
    else
        echo "error: wibo not found; install it, place it at tools/match/bin/wibo, or set WIBO=/path/to/wibo" >&2
        exit 1
    fi
elif [ "${WIBO#*/}" != "$WIBO" ]; then
    if [ ! -x "$WIBO" ]; then
        echo "error: WIBO=$WIBO is not executable" >&2
        exit 1
    fi
elif ! command -v "$WIBO" >/dev/null 2>&1; then
    echo "error: WIBO=$WIBO not found on PATH" >&2
    exit 1
fi

# wibo accepts Z:-prefixed host paths, so Unix paths become Windows include paths.
INCLUDE="Z:$(echo "$MSVC_ROOT/Include" | tr '/' '\\')"
INCLUDE="$INCLUDE;Z:$(echo "$MATCH_ROOT/include" | tr '/' '\\')"
INCLUDE="$INCLUDE;Z:$(echo "$REPO_ROOT/third_party/headers" | tr '/' '\\')"
export INCLUDE

CL_EXE="$MSVC_ROOT/Bin/CL.EXE"
[ -f "$CL_EXE" ] || CL_EXE="$MSVC_ROOT/Bin/cl.exe"

exec "$WIBO" "$CL_EXE" /nologo "$@"
