#!/usr/bin/env bash
set -euo pipefail

out_path="${1:-tools/ast-grep/parsers/zig.so}"
repo_url="https://github.com/tree-sitter-grammars/tree-sitter-zig.git"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

git clone --depth 1 "$repo_url" "$tmp_dir/tree-sitter-zig"

src_dir="$tmp_dir/tree-sitter-zig/src"
mkdir -p "$(dirname "$out_path")"

if [[ -f "$src_dir/scanner.cc" ]]; then
  c++ -O2 -fPIC -shared -I"$src_dir" "$src_dir/parser.c" "$src_dir/scanner.cc" -o "$out_path"
elif [[ -f "$src_dir/scanner.c" ]]; then
  cc -O2 -fPIC -shared -I"$src_dir" "$src_dir/parser.c" "$src_dir/scanner.c" -o "$out_path"
else
  cc -O2 -fPIC -shared -I"$src_dir" "$src_dir/parser.c" -o "$out_path"
fi

echo "Built zig parser at $out_path"
