# grim_zlib_status_is_error

## Plausibility pass (2026-09-27)

Each tolerated status returns `false` from its own case. Separate case bodies keep native's `sub`/`dec` chain before cross-jumping merges them; fall-through cases would become a range check. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

Native target: `grim.dll` at `0x1000a820..0x1000a835` (21 bytes).

The helper classifies zlib statuses `Z_OK`, `Z_STREAM_END`, and `Z_NEED_DICT`
as non-errors and every other status as an error. Separate switch cases recover
the native VC6 decrement-and-branch dispatch exactly.

The VC6 `/O2 /GB /MD` function is an exact 11-instruction match.

The native audit retains this isolated scratch as the canonical baseline, then
validates the helper again under the island's shared `/GX /MD` profile as the
second member of `grim-jaz-decode-island`.
