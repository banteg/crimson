# Grim2D API vtable (draft)

This is a first-pass extraction of the Grim2D API vtable usage from the
classic `crimsonland.exe` decompilation. The engine interface pointer is
`DAT_0048083c` in `source/decompiled/crimsonland.exe_decompiled.c`.

## Extraction artifact

We extracted all `(*DAT_0048083c + offset)` callsites and wrote them to:

- `source/decompiled/grim2d_vtable_calls.csv`

The CSV includes offset, callsite count, unique functions, and sample lines.

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

## Next steps

1. Map each offset to grim.dll call sites (match argument shapes).
2. Assign provisional names in a `grim_api.h` draft.
3. Validate with runtime behavior (config toggles, input, draw calls).
