# `quest_build_fallback`

High-confidence 150-byte WIP with the same 32-instruction multiset as the
native and all seven masked references aligned. The remaining difference is
VC6 scheduling: the native completes each two-float position copy before
interleaving the independent integer field stores, while the candidate moves
some of those stores across the x87 work.

Live Binary Ninja shows the fallback selected by `quest_start_selected` when a
quest has no builder. It logs the fallback, then creates two template `0x40`
waves at x = -50 and vertical terrain center. They trigger at 500 and 5000 ms
with counts 10 and 20, respectively, and publish a two-entry table.

The native intentionally does not initialize either entry's heading. The
reusable eight-byte stack temporary and raw pair copies reveal that the
original entry held a C++ two-float vector, rather than two unrelated scalar
position fields. This scratch preserves both facts instead of zero-filling the
structure or flattening away the vector construction.
