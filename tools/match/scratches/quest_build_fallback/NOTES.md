# `quest_build_fallback`

High-confidence 150-byte WIP with the same 32-instruction multiset as the
native, all seven masked references aligned, and an 87.50% order-sensitive
score. Modeling the three integer metadata fields with the same inline
`set_spawn` member shape recovered in the staged quest builders keeps the
entire second entry in native order and improves the prior 78.12% candidate.

The remaining difference is confined to the first entry. VC6 moves its
template, trigger, and count stores through the still-live x87 height result,
where native finishes the two-float position copy first; it also swaps the
independent second height load and cached `-50.0f` load. The source retains the
ordinary member call rather than adding an artificial ordering dependency.

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
