# Detangling notes

**Status:** In progress

This page tracks high-value functions to name and the evidence gathered so far.
Use the hotspot script to refresh the lists when the decompile is regenerated.

## Hotspot script

```
uv run python scripts/function_hotspots.py --top 12 --only-fun
```

## Name map workflow

We keep authoritative renames/signatures in `source/ghidra/name_map.json` and
apply them during headless analysis:

```
./.codex/skills/ghidra/scripts/ghidra-analyze.sh \
  --script-path scripts/ghidra_scripts \
  -s ApplyNameMap.java -a source/ghidra/name_map.json \
  -s ExportAll.java -o source/decompiled game/crimsonland.exe
```

You can also set `CRIMSON_NAME_MAP` to point at a custom map.

## High-call functions (current)

### `crimsonland.exe`

```
  36    2 00401870 FUN_00401870 undefined FUN_00401870(void * param_1, byte * param_2)
  32    6 004566d3 FUN_004566d3 int FUN_004566d3(int param_1)
  31    1 004658cc FUN_004658cc undefined FUN_004658cc(int param_1)
  26    7 0046586b FUN_0046586b undefined FUN_0046586b(int param_1)
  25    1 00465d93 FUN_00465d93 DWORD * FUN_00465d93(void)
  20    1 00460d86 FUN_00460d86 int FUN_00460d86(undefined4 param_1)
  19    0 0042fcf0 FUN_0042fcf0 undefined4 FUN_0042fcf0(int param_1)
  15    2 004616e7 FUN_004616e7 int FUN_004616e7(undefined1 * param_1, byte * param_2)
  14    8 004654b8 FUN_004654b8 DWORD * FUN_004654b8(void)
  14    1 00460dc7 FUN_00460dc7 undefined FUN_00460dc7(undefined * param_1)
  14    1 00465d9c FUN_00465d9c DWORD * FUN_00465d9c(void)
  14    0 0042e120 FUN_0042e120 undefined4 * FUN_0042e120(int param_1, undefined4 * param_2)
```

### `grim.dll`

```
  33    0 10016944 FUN_10016944 undefined4 FUN_10016944(void * this, int param_1)
  32    6 1001c188 FUN_1001c188 int FUN_1001c188(int param_1)
  32    1 100170f9 FUN_100170f9 undefined4 * FUN_100170f9(void * this, undefined4 * param_1, uint param_2, undefined4 param_3)
  30    0 100170d6 FUN_100170d6 undefined FUN_100170d6(undefined4 param_1)
  28    0 100174a8 FUN_100174a8 undefined FUN_100174a8(void * this, uint param_1)
  21    0 1004b5b0 FUN_1004b5b0 undefined FUN_1004b5b0(void)
  14    1 1001e114 FUN_1001e114 undefined FUN_1001e114(int * param_1, undefined4 param_2)
  10    0 10001160 FUN_10001160 undefined FUN_10001160(void)
  10    0 1001e132 FUN_1001e132 undefined FUN_1001e132(int param_1, undefined4 param_2)
   9    4 100250d7 FUN_100250d7 undefined4 FUN_100250d7(int * param_1, uint param_2)
   9    2 10024807 FUN_10024807 undefined FUN_10024807(int * param_1, byte * param_2, uint param_3)
   8    2 1001029e FUN_1001029e undefined FUN_1001029e(int param_1)
```

## Identified candidates

### Logging / console queue (high confidence)

- `FUN_0046e8f4` -> `strdup_malloc`
  - Evidence: `strlen` + `malloc` + copy (`FUN_00465c30`) pattern.
- `FUN_004017a0` -> `console_push_line`
  - Evidence: pushes strdup’d strings into a list, caps at 0x1000 entries.
- `FUN_00401870` -> `console_printf`
  - Evidence: formats strings (uses `FUN_00461089`) then pushes into the console queue; callsites include `Unknown command`/CMOD logs.

### Renderer backend selection (medium confidence)

- `FUN_004566d3` -> `renderer_select_backend`
  - Evidence: copies a function table, reads config `DisableD3DXPSGP`,
    and switches between multiple vtable variants (`FUN_004567b0`, `FUN_004568c0`, `FUN_00456aa5`).

### Texture loading helpers (high confidence)

- `FUN_0042a670` -> `texture_get_or_load`
  - Evidence: calls Grim `get_texture_handle` (0xc0); if missing, calls `load_texture` (0xb4),
    logs success/failure, and re-queries handle.
- `FUN_0042a700` -> `texture_get_or_load_alt`
  - Evidence: identical body to `texture_get_or_load`; primary callers pass `.jaz` assets.

## Next naming targets

- Trace `FUN_0046586b` / `FUN_004658cc` (called by error paths); likely error reporting or fatal handling.
- Resolve `FUN_00465d93` / `FUN_00465d9c` (errno getters?) referenced from string parsing.
- For `grim.dll`, inspect `FUN_10016944` (coordinate conversions and vertex packing) to pin down the render pipeline stage.
