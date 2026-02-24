#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

zig build wasm

wasm_file="$(ls -1 zig-out/bin/*.wasm | head -n1)"
if [[ -z "$wasm_file" ]]; then
  echo "wasm artifact not found" >&2
  exit 1
fi

node - <<'JS' "$wasm_file"
const fs = require('node:fs');

(async () => {
  const wasmPath = process.argv[2];
  const bytes = fs.readFileSync(wasmPath);
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const e = instance.exports;

  const required = [
    'crimson_alloc',
    'crimson_free',
    'crimson_verify_replay_json',
    'crimson_last_error_json',
  ];
  for (const name of required) {
    if (!(name in e)) {
      throw new Error(`missing export: ${name}`);
    }
  }
  console.log('wasm smoke ok');
})();
JS
