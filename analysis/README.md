# Analysis workflow

`analysis/ghidra/maps/name_map.json` and `data_map.json` are the shared analysis
state. Decompiled text is a view of that state, not a checked-in source of
truth.

Deterministic canonical-object and symbol-closure artifacts for the native
linker track live under [`analysis/native/`](native/README.md).

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

`uv run scripts/analysis_view.py show` remains a lightweight curated-map view when matcher
state is not needed.

Check that the structured snapshots still agree with the curated map:

```bash
uv run scripts/analysis_view.py check --program crimsonland.exe
uv run scripts/analysis_view.py check --program grim.dll
```

Add `--binja-live` to include an open Binary Ninja session:

```bash
uv run scripts/analysis_view.py check --program crimsonland.exe --binja-live
```

Refresh an already-open Binary Ninja database from the shared maps:

```bash
bn py exec --target crimsonland.exe.bndb --script scripts/binja_import_maps.py --format text --no-spill
bn py exec --target grim.dll.bndb --script scripts/binja_import_maps.py --format text --no-spill
```

The [IDA](ida/README.md) and [Ghidra](ghidra/README.md) runbooks document
refreshing their structured snapshots directly with the tool scripts. IDA
reopens the gitignored database under `analysis/ida/databases/`; Ghidra reopens
the gitignored project under `analysis/ghidra/projects/`. Both reapply the
shared maps and replace their structured snapshots after analysis.

Each persistent database has a provenance record containing the input binary
hash and analysis-tool version/fingerprint. A mismatch is a hard error so a
database cannot silently be reused for a different binary or tool build.

Use the tool scripts' `--rebuild` option to create a clean database when
validating reproducibility or after an intentional input/tool change; see the
runbooks above for the complete invocations.

Rebuild commands move the prior local database/project and provenance into an
ignored `backups/` directory before starting clean.

Tool-specific presentation hints live under `analysis/overlays/`. Recovered
behavioral notes that used to exist only in editable Ghidra hotspot copies live
under `analysis/annotations/`.

Do not cite generated line numbers. Cite the canonical function name and
address, for example `player_update` at `0x004136b0`, and use the commands above
to refresh the current tool view.
