#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ida-export.sh <binary> <output-dir>

Environment:
  IDA_BIN  Path to the headless IDA executable.
EOF
}

if [[ $# -ne 2 ]]; then
    usage >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
binary="$1"
output_dir="$2"
ida_bin="${IDA_BIN:-/Applications/IDA Professional 9.3.app/Contents/MacOS/idat}"

if [[ "$binary" != /* ]]; then
    binary="$repo_root/$binary"
fi
if [[ "$output_dir" != /* ]]; then
    output_dir="$repo_root/$output_dir"
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

temp_binary="$temp_dir/$(basename "$binary")"
cp "$binary" "$temp_binary"
mkdir -p "$output_dir"

script="$repo_root/scripts/ida_export.py"
name_map="$repo_root/analysis/ghidra/maps/name_map.json"
data_map="$repo_root/analysis/ghidra/maps/data_map.json"

"$ida_bin" \
    -A \
    -c \
    -L"$temp_dir/ida.log" \
    "-S$script $output_dir $name_map $data_map" \
    "$temp_binary"
