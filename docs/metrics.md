# Progress metrics

**Status:** Tracking

This page tracks how much of the game we have decoded or reversed. Update the
numbers after each Ghidra regen or when a format/system is confirmed.

## Binary coverage

Counts come from `source/decompiled/*_summary.txt` and
`source/decompiled/ghidra_analysis.log`.

| Binary | Total funcs | Thunks | User-defined | Decompiled | Coverage | Last regen |
| ------ | ----------- | ------ | ------------ | ---------- | -------- | ---------- |
| `crimsonland.exe` | 819 | 26 | 793 | 790 | 99.6% | 2026-01-16 |
| `grim.dll` | 883 | 40 | 843 | 843 | 100% | 2026-01-16 |
| **Total** | 1702 | 66 | 1636 | 1633 | 99.8% | 2026-01-16 |

## Formats and systems

| Area | Status | Notes |
| ---- | ------ | ----- |
| PAQ archives | Completed | `docs/formats/paq.md` |
| JAZ textures | Completed | `docs/formats/jaz.md` |
| Sprite atlas cutting | In progress | `docs/atlas.md` |
| Extraction pipeline | In progress | `docs/pipeline.md` |
| Weapon table | In progress | `docs/weapon-table.md` |

## Refactor progress

| Metric | Value | Notes |
| ------ | ----- | ----- |
| Clean C files | 0 | `source/clean/` is currently empty. |
| Header packs | 0 | `source/headers/` is currently empty. |
