# Analysis workflow

`analysis/ghidra/maps/name_map.json` and `data_map.json` are the shared analysis
state. Decompiled text is a view of that state, not a checked-in source of
truth.

Consult a function in this order:

1. Binary Ninja, using the live database and `bn`.
2. IDA, using the same function address and the structured snapshot under
   `analysis/ida/raw/<program>/functions.json`.
3. Ghidra, using the same function address and the structured snapshot under
   `analysis/ghidra/raw/<program>_functions.json`.

Resolve a name or address and see the state recorded by all three tools:

```bash
uv run crimson match inspect player_update
uv run crimson match inspect 0x004136b0
uv run crimson match inspect grim_is_key_down --image grim.dll
```

The matching-aware command prints exact `bn decompile`, `bn il`, `bn disasm`,
and `bn bundle function` invocations for the preferred live view, then joins
the same address to IDA, Ghidra, and any matching scratch. Add `--binja-live`
to save a bounded current Binary Ninja bundle under
`tools/match/.cache/evidence/`. Scratch evaluation is target-local, so this
consultation does not rebuild the full matching corpus.

`just analysis-function` remains a lightweight curated-map view when matcher
state is not needed.

Check that the structured snapshots still agree with the curated map:

```bash
just analysis-check
just analysis-check grim.dll
```

Pass `true` as the second argument to include an open Binary Ninja session:

```bash
just analysis-check crimsonland.exe true
```

Refresh each tool from the shared maps:

```bash
just binja-sync
just ida-export-exe
just ghidra-exe

just binja-sync grim.dll
just ida-export-grim
just ghidra-grim
```

`binja-sync` operates on an already-open Binary Ninja database. IDA and Ghidra
analyze a temporary copy of the binary and replace only their structured
snapshots.

Tool-specific presentation hints live under `analysis/overlays/`. Recovered
behavioral notes that used to exist only in editable Ghidra hotspot copies live
under `analysis/annotations/`.

Do not cite generated line numbers. Cite the canonical function name and
address, for example `player_update` at `0x004136b0`, and use the commands above
to refresh the current tool view.
