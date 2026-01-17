# Progress metrics

**Status:** Tracking

This page tracks how much of the game we have decoded or reversed. Update the
numbers after each Ghidra regen or when a format/system is confirmed.

## Binary coverage

Counts come from `source/decompiled/*_summary.txt` and
`source/decompiled/ghidra_analysis.log`. “Named/inferred” counts functions
whose names are not the default Ghidra stubs (`FUN_*`, `thunk_FUN_*`, `LAB_*`).
“Typed signature” means the function signature does not start with
`undefined`/`undefinedN`. “GDT hits” count signature changes vs the previous
regen (from git history).

### `crimsonland.exe`

- Total funcs: 819
- Thunks: 26
- User-defined: 793
- Decompiled: 792 (99.7% coverage)
- Named/inferred: 94 (11.5%)
- Typed signatures: 230 (28.1%)
- External typed: 0 / 0
- GDT hits (since previous regen): 1
- Last regen: 2026-01-16

### `grim.dll`

- Total funcs: 959
- Thunks: 40
- User-defined: 919
- Decompiled: 919 (100% coverage)
- Named/inferred: 201 (21.0%)
- Typed signatures: 232 (24.2%)
- External typed: 0 / 0
- GDT hits (since previous regen): 0
- Last regen: 2026-01-16

### Total

- Total funcs: 1778
- Thunks: 66
- User-defined: 1712
- Decompiled: 1711 (99.9% coverage)
- Named/inferred: 295 (16.6%)
- Typed signatures: 462 (26.0%)
- External typed: 0 / 0
- GDT hits (since previous regen): 1
- Last regen: 2026-01-16

## Formats and systems

### PAQ archives

- Status: Completed
- Notes: [PAQ format notes](formats/paq.md)

### JAZ textures

- Status: Completed
- Notes: [JAZ format notes](formats/jaz.md)

### Sprite atlas cutting

- Status: In progress
- Notes: [Atlas cutting](atlas.md)

### Extraction pipeline

- Status: In progress
- Notes: [Extraction pipeline](pipeline.md)

### Weapon table

- Status: In progress
- Notes: [Weapon table](weapon-table.md)

## Refactor progress

### Clean C files

- Value: 0
- Notes: `source/clean/` is currently empty.

### Header packs

- Value: 1
- Notes: `source/headers/third_party` (PNG/JPEG/zlib/ogg/vorbis + DirectX/DirectSound refs).
