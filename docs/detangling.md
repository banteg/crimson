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
  25    1 00465d93 FUN_00465d93 DWORD * FUN_00465d93(void)
  20    1 00460d86 FUN_00460d86 int FUN_00460d86(undefined4 param_1)
  19    0 0042fcf0 FUN_0042fcf0 undefined4 FUN_0042fcf0(int param_1)
  15    2 004616e7 FUN_004616e7 int FUN_004616e7(undefined1 * param_1, byte * param_2)
  15    0 0042e120 FUN_0042e120 undefined4 * FUN_0042e120(int param_1, undefined4 * param_2)
  14    3 0043d120 FUN_0043d120 int FUN_0043d120(int param_1)
  14    1 00460dc7 FUN_00460dc7 undefined FUN_00460dc7(undefined * param_1)
  14    1 00465d9c FUN_00465d9c DWORD * FUN_00465d9c(void)
  12    8 004625c1 FUN_004625c1 undefined FUN_004625c1(undefined * param_1)
  12    3 00460e5d FUN_00460e5d undefined4 FUN_00460e5d(FILE * param_1)
  12    2 0043d550 FUN_0043d550 undefined FUN_0043d550(int param_1)
  11    3 0043d260 FUN_0043d260 float FUN_0043d260(float param_1)
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

### CRT errno accessors (high confidence)

- `FUN_00465d93` -> `crt_errno_ptr` (`_errno`-style accessor)
- `FUN_00465d9c` -> `crt_doserrno_ptr` (`__doserrno`-style accessor)
- Evidence:
  - Both call `crt_get_thread_data()` and return pointer offsets (`+2`, `+3`).
  - `FUN_00465d20` stores Win32 errors into `*FUN_00465d9c` and maps to `*FUN_00465d93`
    via the error table at `DAT_0047b7c0`.
  - File I/O wrappers set these directly on failure:
    - `FUN_004655bf` (FlushFileBuffers) stores `GetLastError()` in `*FUN_00465d9c` and sets
      `*FUN_00465d93 = 9` (EBADF).
    - `FUN_004656b7` (WriteFile) and `FUN_00466064` (ReadFile) call `FUN_00465d20` after
      `GetLastError()` for non-trivial errors.
    - `FUN_0046645e` (SetFilePointer) maps `GetLastError()` through `FUN_00465d20`.

### CRT lock/unlock helpers (high confidence)

- `FUN_0046586b` -> `crt_lock`
  - Evidence: calls `InitializeCriticalSection`, `EnterCriticalSection`, and `__amsg_exit` in the
    lock path; invoked by `crt_exit_lock` and many CRT wrappers.
- `FUN_004658cc` -> `crt_unlock`
  - Evidence: calls `LeaveCriticalSection`; invoked by `crt_exit_unlock` and many CRT wrappers.

### CRT exit/stdio helpers (high confidence)

- `FUN_00460d08` -> `crt_onexit`
  - Evidence: takes exit callback, grows onexit table (`DAT_004db4f4`/`DAT_004db4f0`) via
    `FUN_004626aa`, stores pointer, and wraps with `crt_exit_lock`/`crt_exit_unlock`.
- `FUN_00460d86` -> `crt_atexit`
  - Evidence: calls `crt_onexit` and returns `0` on success, `-1` on failure.
- `FUN_00460dc7` -> `crt_free`
  - Evidence: thin wrapper around `FUN_004625c1` (CRT heap free).
- `FUN_004625c1` -> `crt_free_base`
  - Evidence: checks heap mode (`DAT_004da3a8`), locks heap, frees via small-block helpers, and
    falls back to `HeapFree`.
- `FUN_00460e5d` -> `crt_fclose`
  - Evidence: if `_flag & 0x40` not set, locks stream, calls `__fclose_lk`, unlocks; otherwise
    clears `_flag`.
- `FUN_004616e7` -> `crt_sprintf`
  - Evidence: uses CRT output core `FUN_00464380` with an unbounded count (`0x7fffffff`) and
    terminates with `\0` on success.

### Audio SFX helpers (medium confidence)

- `FUN_0043d120` -> `sfx_play`
  - Evidence: validates entry in `DAT_004c84e4`, checks cooldown `DAT_004c3c80`, sets sample rate
    via `_DAT_00487014` into `DAT_00477d28`, chooses a voice (`FUN_0043be60`), calls vtable +0x40
    with pan 0, then sets volume with `FUN_0043bfa0`.
- `FUN_0043d260` -> `sfx_play_panned`
  - Evidence: same as `sfx_play`, but converts an FPU value to pan (`__ftol`), clamps to
    `[-10000, 10000]`, and passes pan to vtable +0x40.
- `FUN_0043d550` -> `sfx_mark_muted`
  - Evidence: sets `DAT_004c8450[sfx]=1` and recursively applies to other unmuted ids using
    `FUN_0043d7c0`; `FUN_0043d460` later clears the chosen id for exclusive playback.

### Global var access (medium confidence)

- `FUN_0042fcf0` -> `game_var_get`
  - Evidence: returns `(&DAT_00490968)[id]` directly; the table is used as a global int registry
    (perk/config gating, counters).

### Effect spawn helper (medium confidence)

- `FUN_0042de80` -> `effect_init_entry`
  - Evidence: zeros/sets default fields on a single entry and initializes per-quad color slots.
- `FUN_0042df10` -> `effect_defaults_reset`
  - Evidence: resets global template values (`DAT_004ab1*`) used by effect spawners.
- `FUN_0042e080` -> `effect_free`
  - Evidence: pushes the entry back onto `DAT_004c2b30` free list and clears live flag.
- `FUN_0042e0a0` -> `effect_select_texture`
  - Evidence: maps effect id through `DAT_004755f0/4` and calls Grim vtable +0x104 with
    texture page bitmasks.
- `FUN_0042e120` -> `effect_spawn`
  - Evidence: pops an entry from the pool `DAT_004c2b30`, copies template `DAT_004ab1bc`,
    writes position from `param_2`, tags the effect id, and assigns quad UVs from atlas tables
    `DAT_004755f0/4` plus arrays `DAT_004aa4d8`, `DAT_00491010`, `DAT_00491210`, `DAT_00491290`.
- `FUN_0042e710` -> `effects_update`
  - Evidence: iterates pool entries, advances timers/positions with `DAT_00480840`, and calls
    `effect_free` when expired.
- `FUN_0042e820` -> `effects_render`
  - Evidence: sets render state, iterates effects, computes rotated quad vertices, and submits
    via Grim vtable +0x134.

### Perk database + selection (medium confidence)

- `FUN_0042fd90` -> `perks_init_database`
  - Evidence: assigns perk id constants (`DAT_004c2b**`/`DAT_004c2c**`) and fills the perk
    name/description tables via `FUN_0042fd00`.
  - See `docs/perk-id-map.md` for the extracted id-to-name mapping.
- `FUN_0042fb10` -> `perk_can_offer`
  - Evidence: checks mode gates and perk flags, then returns a nonzero byte if the perk is eligible.
- `FUN_0042fbd0` -> `perk_select_random`
  - Evidence: randomizes an id from the perk table, calls `perk_can_offer`, and logs a failure when
    selection runs too long.
- `FUN_0042fc30` -> `perks_rebuild_available`
  - Evidence: resets `DAT_004c2c4c` flags and re-enables base/unlocked perks.

## Next naming targets

- For `grim.dll`, inspect `FUN_10016944` (coordinate conversions and vertex packing) to pin down the render pipeline stage.
