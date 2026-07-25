#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ida-export.sh <binary> <output-dir>

Environment:
  IDA_BIN  Path to the headless IDA executable.
  IDAUSR   Source IDA user directory. Its accepted ida.reg is copied into
           isolated temporary state for the headless run.
EOF
}

if [[ $# -ne 2 ]]; then
    usage >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
binary="$1"
output_dir="$2"
ida_bin="${IDA_BIN:-/Applications/IDA Professional 9.4.app/Contents/MacOS/idat}"

if [[ "$binary" != /* ]]; then
    binary="$repo_root/$binary"
fi
if [[ "$output_dir" != /* ]]; then
    output_dir="$repo_root/$output_dir"
fi
metadata_binary="$binary"
if [[ "$binary" == "$repo_root/"* ]]; then
    metadata_binary="${binary#"$repo_root"/}"
fi

if [[ ! -f "$binary" ]]; then
    echo "Binary not found: $binary" >&2
    exit 1
fi
if [[ ! -x "$ida_bin" ]]; then
    echo "Headless IDA not found: $ida_bin" >&2
    exit 1
fi

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/crimson-ida.XXXXXX")"
cleanup() {
    rm -rf -- "$temp_dir"
}
trap cleanup EXIT

source_ida_user_dir="${IDAUSR:-$HOME/.idapro}"
source_ida_registry="$source_ida_user_dir/ida.reg"
if [[ ! -f "$source_ida_registry" ]]; then
    echo "IDA registry not found: $source_ida_registry" >&2
    echo "Launch IDA once and accept its license before running headlessly." >&2
    exit 1
fi

isolated_ida_user_dir="$temp_dir/ida-user"
mkdir -p "$isolated_ida_user_dir"
cp "$source_ida_registry" "$isolated_ida_user_dir/ida.reg"

temp_binary="$temp_dir/$(basename "$binary")"
cp "$binary" "$temp_binary"
mkdir -p "$output_dir"

script="$repo_root/scripts/ida_export.py"
name_map="$repo_root/analysis/ghidra/maps/name_map.json"
data_map="$repo_root/analysis/ghidra/maps/data_map.json"

IDAUSR="$isolated_ida_user_dir" "$ida_bin" \
    -A \
    -c \
    -L"$temp_dir/ida.log" \
    "-S$script $output_dir $name_map $data_map $metadata_binary" \
    "$temp_binary"
