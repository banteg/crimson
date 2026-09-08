# crt_pow_entry

Exact nine-byte public entry prefix from the pinned VC6 SP6 CRT archive.
The native manifest boundary is a fallthrough into a separately catalogued
shared implementation, not a return. Two instructions and one REL32 call
reference match; encoded-body identity is true.

See `tools/match/CRT-MATH-ENTRIES-2026-09-08.md` for offsets, ownership, and
the distinction between entry-fragment matching and whole archive linking.
