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
- Named/inferred: 199 (24.3%)
- Typed signatures: 314 (38.3%)
- External typed: 0 / 0
- GDT hits (since previous regen): 1
- Last regen: 2026-01-17


### `grim.dll`

- Total funcs: 968
- Thunks: 41
- User-defined: 927
- Decompiled: 927 (100% coverage)
- Named/inferred: 218 (22.5%)
- Typed signatures: 287 (29.6%)
- External typed: 0 / 0
- GDT hits (since previous regen): 0
- Last regen: 2026-01-16


### Total

- Total funcs: 1787
- Thunks: 67
- User-defined: 1720
- Decompiled: 1719 (99.9% coverage)
- Named/inferred: 417 (23.3%)
- Typed signatures: 601 (33.6%)
- External typed: 0 / 0
- GDT hits (since previous regen): 1
- Last regen: 2026-01-17


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
