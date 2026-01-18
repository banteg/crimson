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


## Ghidra map progress

Counts come from `analysis/ghidra/maps/name_map.json` and
`analysis/ghidra/maps/data_map.json`. Run
`uv run python scripts/update_map_progress_docs.py` to refresh.

<!-- map-progress:start -->
| Map | Total entries | crimsonland.exe | grim.dll | With signatures | With comments | Duplicate names |
| --- | --- | --- | --- | --- | --- | --- |
| Name map | 491 | 318 | 173 | 462 | 468 | 0 |
| Data map | 718 | 632 | 86 | n/a | 718 | 0 |
<!-- map-progress:end -->

### Data map coverage (decompiled symbols)

Coverage is based on the decompiled C output, counting unique `DAT_*`/`PTR_DAT_*`
symbols plus applied data-map labels. Run
`uv run python scripts/update_map_progress_docs.py` to refresh.

<!-- data-map-coverage:start -->
| Program | Labeled symbols | Total data symbols | Coverage |
| --- | --- | --- | --- |
| crimsonland.exe | 557 | 2790 | 19.96% |
| grim.dll | 69 | 476 | 14.50% |
| Total | 626 | 3266 | 19.17% |
<!-- data-map-coverage:end -->


## Docs

### Formats and systems

#### PAQ archives

- Status: Completed
- Notes: [PAQ format notes](formats/paq.md)


#### JAZ textures

- Status: Completed
- Notes: [JAZ format notes](formats/jaz.md)


#### Sprite atlas cutting

- Status: In progress
- Notes: [Atlas cutting](atlas.md)


#### Extraction pipeline

- Status: In progress
- Notes: [Extraction pipeline](pipeline.md)


#### Weapon table

- Status: In progress
- Notes: [Weapon table](weapon-table.md)


### Data tables

| Doc | Entries | Notes |
| --- | --- | --- |
| [Weapon table](weapon-table.md) | 42 (40 named) | 2 unnamed entries in `WEAPON_TABLE`. |
| [Perk ID map](perk-id-map.md) | 58 | IDs 0-57 listed. |
| [Bonus ID map](bonus-id-map.md) | 15 | IDs 0-14 listed; id 0 unused. |
| [Game mode map](game-mode-map.md) | 5 | Includes hidden tutorial mode. |
| [SFX ID map](sfx-id-map.md) | 72 + 3 aliases | Main map plus alias table. |
| [SFX labels](sfx-labels.md) | 72 + 3 aliases | Derived from the SFX ID map. |
| [SFX usage](sfx-usage.md) | 40 | Top callsite rows listed. |

## Rewrite progress

### Zig modules

- Value: 0
- Notes: `rewrite/` is the canonical clean layer; no Zig modules committed yet.


### Header packs

- Value: 1
- Notes: `third_party/headers` (PNG/JPEG/zlib/ogg/vorbis + DirectX/DirectSound refs).
