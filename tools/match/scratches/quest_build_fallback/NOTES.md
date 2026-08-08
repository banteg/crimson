# `quest_build_fallback`

The recovered source matches all 150 native bytes and all 32 instructions,
including the full prefix and all seven masked references. Modeling the three
metadata fields with the inline `set_spawn` member and publishing both entries
through one append count gives VC6 the native position/metadata schedule
without an artificial ordering dependency.

Live Binary Ninja shows the fallback selected by `quest_start_selected` when a
quest has no builder. It logs the fallback, then creates two template `0x40`
waves at x = -50 and vertical terrain center. They trigger at 500 and 5000 ms
with counts 10 and 20, respectively, and publish a two-entry table.

The importer now gives fixed-index `quest_build_*` first parameters a
layout-equivalent `quest_spawn_entries_binja_t` presentation view. Binary Ninja
therefore renders this function as `table->entries[0]` and
`table->entries[1]`, including named position, template, trigger, and count
fields, instead of losing the second record behind raw `__offset(0x18)` through
`__offset(0x2c)` stores. The canonical compiler-facing pointer remains
`quest_spawn_entry_t *`, so this decompiler-only view is byte-neutral.
Loop-heavy builders retain that canonical pointer in Binary Ninja as well:
its 0x18 stride gives their advancing entry cursors a clearer representation
than the fixed-table wrapper. A complete post-import HLIL inventory fell from
553 raw offsets to 129; the remaining quest occurrences are induction-pointer
artifacts rather than unknown record fields.

The native intentionally does not initialize either entry's heading. The
reusable eight-byte stack temporary and raw pair copies reveal that the
original entry held a C++ two-float vector, rather than two unrelated scalar
position fields. This scratch preserves both facts instead of zero-filling the
structure or flattening away the vector construction.

## Recorded first-entry search

`entry-copy-schedule-mutations.json` exhaustively evaluated 62 single and pair
combinations over the first-entry copy, metadata stores, height calculation,
and second-entry setup. None improved the 87.50% baseline (spec
`061931b9ed1e1a2923722c113d4892f9c79da7a8dfe7c144b1b6bacda59d58b5`).
The complete negative matrix is recorded in `experiments.jsonl`.

## 2026-08-08 exact recovery

Replacing the two fixed indices and fixed output assignment with one append
count resolves the former first-entry scheduling residual. The candidate
improves from 131/150 fuzzy-weighted bytes (87.50%) and a 12-instruction prefix
to exact 150/150 bytes and a 32-instruction prefix. References remain 7/0/0.
The exact source SHA-256 is
`9c2e6491b1fd56e89ce3bb6e7885e5ff0f097af3be1ca113e38dd9c71ee1669e`.
