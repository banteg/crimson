# Progress metrics

**Status:** Tracking

This page tracks how much of the game we have decoded or reversed. Update the
numbers after each Ghidra regen or when a format/system is confirmed.

## Binary coverage

Counts come from `analysis/ghidra/raw/*_summary.txt` and
`analysis/ghidra/raw/ghidra_analysis.log`. “Named/inferred” counts functions
whose names are not the default Ghidra stubs (`FUN_*`, `thunk_FUN_*`, `LAB_*`).
“Typed signature” means the function signature does not start with
`undefined`/`undefinedN`. “GDT hits” count signature changes vs the previous
regen (from git history).

### `crimsonland.exe`

- Total funcs: 819
- Thunks: 26
- User-defined: 793
- Decompiled: 792 (99.9% coverage)
- Named/inferred: 233 (28.4%)
- Typed signatures: 325 (39.7%)
- External typed: 0 / 0
- GDT hits (since previous regen): 1
- Last regen: 2026-01-17


### `grim.dll`

- Total funcs: 960
- Thunks: 40
- User-defined: 920
- Decompiled: 920 (100% coverage)
- Named/inferred: 235 (24.5%)
- Typed signatures: 261 (27.2%)
- External typed: 0 / 0
- GDT hits (since previous regen): 0
- Last regen: 2026-01-17


### Total

- Total funcs: 1779
- Thunks: 66
- User-defined: 1713
- Decompiled: 1712 (99.9% coverage)
- Named/inferred: 468 (26.3%)
- Typed signatures: 586 (32.9%)
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


## Rewrite progress

### Zig modules

- Value: 0
- Notes: `rewrite/` is the canonical clean layer; no Zig modules committed yet.


### Header packs

- Value: 1
- Notes: `third_party/headers` (PNG/JPEG/zlib/ogg/vorbis + DirectX/DirectSound refs).
