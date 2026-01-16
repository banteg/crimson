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
- Named/inferred: 86 (10.5%)
- Typed signatures: 231 (28.2%)
- External typed: 0 / 0
- GDT hits (since previous regen): 8
- Last regen: 2026-01-16

### `grim.dll`

- Total funcs: 959
- Thunks: 40
- User-defined: 919
- Decompiled: 919 (100% coverage)
- Named/inferred: 146 (15.2%)
- Typed signatures: 181 (18.9%)
- External typed: 0 / 0
- GDT hits (since previous regen): 1
- Last regen: 2026-01-16

### Total

- Total funcs: 1778
- Thunks: 66
- User-defined: 1712
- Decompiled: 1711 (99.9% coverage)
- Named/inferred: 232 (13.0%)
- Typed signatures: 412 (23.2%)
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
