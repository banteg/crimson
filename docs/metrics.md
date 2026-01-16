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
- Decompiled: 790 (99.6% coverage)
- Named/inferred: 50 (6.1%)
- Typed signatures: 227 (27.7%)
- External typed: 0 / 0
- GDT hits (since previous regen): 8
- Last regen: 2026-01-16

### `grim.dll`

- Total funcs: 883
- Thunks: 40
- User-defined: 843
- Decompiled: 843 (100% coverage)
- Named/inferred: 106 (12.0%)
- Typed signatures: 148 (16.8%)
- External typed: 0 / 0
- GDT hits (since previous regen): 1
- Last regen: 2026-01-16

### Total

- Total funcs: 1702
- Thunks: 66
- User-defined: 1636
- Decompiled: 1633 (99.8% coverage)
- Named/inferred: 156 (9.2%)
- Typed signatures: 375 (22.0%)
- External typed: 0 / 0
- GDT hits (since previous regen): 9
- Last regen: 2026-01-16

## Formats and systems

### PAQ archives

- Status: Completed
- Notes: `docs/formats/paq.md`

### JAZ textures

- Status: Completed
- Notes: `docs/formats/jaz.md`

### Sprite atlas cutting

- Status: In progress
- Notes: `docs/atlas.md`

### Extraction pipeline

- Status: In progress
- Notes: `docs/pipeline.md`

### Weapon table

- Status: In progress
- Notes: `docs/weapon-table.md`

## Refactor progress

### Clean C files

- Value: 0
- Notes: `source/clean/` is currently empty.

### Header packs

- Value: 1
- Notes: `source/headers/third_party` (PNG/JPEG/zlib/ogg/vorbis + DirectX/DirectSound refs).
