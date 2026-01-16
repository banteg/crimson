# Grim2D API vtable (draft)

This is a first-pass extraction of the Grim2D API vtable usage from the
classic `crimsonland.exe` decompilation. The engine interface pointer is
`DAT_0048083c` in `source/decompiled/crimsonland.exe_decompiled.c`.

The interface is created in `GRIM__GetInterface` (`grim.dll`), which sets the
object vtable to `PTR_LAB_1004c238` (address `0x1004c238` in the DLL).

We created functions at vtable entry addresses via
`scripts/ghidra_scripts/CreateGrim2DVtableFunctions.java` and re-exported
`grim.dll_functions.json` to capture those entry names. The latest vtable CSVs
now include 84 named entry points.

## Extraction artifact

We extracted all `(*DAT_0048083c + offset)` callsites and wrote them to:

- `source/decompiled/grim2d_vtable_calls.csv`

The CSV includes offset, callsite count, unique functions, and sample lines.

We also dumped the Grim2D vtable itself from `game/grim.dll` and joined the
two datasets:

- `source/decompiled/grim2d_vtable_entries.csv`
- `source/decompiled/grim2d_vtable_map.csv`

The map CSV includes function size, calling convention, return type, parameter
count, and the raw Ghidra signature for faster triage.

## Top offsets by callsite count

These are the most frequently used offsets (likely the core draw/state calls):

- `0x20` (206)
- `0x114` (203)
- `0x11c` (100)
- `0xf0` (86)
- `0x148` (86)
- `0xe8` (79)
- `0xc4` (66)
- `0xfc` (65)
- `0x100` (59)
- `0x48` (39)

## Input-ish offsets (evidence)

These offsets appear with keycodes or input-related values:

- `0x44` / `0x48` used with keycodes like `0x1d`, `0x9d`, `0xd0`, `200`
  in `FUN_00401a40` (likely key down / key pressed checks).
- `0x50` is a zero-arg call in `FUN_00401060` (likely a per-frame poll).
- `0x58` / `0x80` appear in input handling loops in `FUN_00446030`.
- `0x84` returns a float and is queried with IDs `0x13f..0x155`
  in `FUN_00448b50` (likely config values).

## Initial mapping (best guesses)

These are high-confidence candidates based on call patterns:

- `0x20` — render state setter (`(0x13,5)`, `(0x14,6)`, `(0x18,0x3f000000)`),
  matches D3D-style `SetRenderState` usage.
- `0xb4` — load texture by name; called as `(name, name)` and returns success.
- `0xc0` — get texture handle by name; returns `-1` if missing.
- `0xac` — create terrain texture (`"ground"`, width, height); returns success.
- `0x44` — key-down (used with Ctrl codes `0x1d/0x9d`).
- `0x48` — key-pressed / edge trigger (used with arrows, pgup/pgdn).
- `0x58` — mouse button state (called with `0`).
- `0x80` — key state lookup (called with key mapping entries).
- `0x100` — set UVs / texture coords (four floats).
- `0x104` — set sprite frame / atlas index (called with `(8, frame)`).
- `0x108` — set sub-rect in pixels (stacked 4 args before draw).
- `0x110` — set rotation pivot / center (takes pointer to float(s)).
- `0xfc` — set rotation angle (radians).
- `0x114` — set color/alpha (RGBA floats).
- `0x11c` — draw quad (x, y, w, h).
- `0x144` — draw text (x, y, string).
- `0x148` — draw text with layout/wrapping (x, y, string, optional args).
- `0x14c` — text metrics (returns width/height; sometimes no args).

## Next steps

1. Map each offset to grim.dll call sites (match argument shapes).
2. Assign provisional names in a `grim_api.h` draft.
3. Validate with runtime behavior (config toggles, input, draw calls).
