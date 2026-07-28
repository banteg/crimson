# grim_zlib_status_is_error

Native target: `grim.dll` at `0x1000a820..0x1000a835` (21 bytes).

The helper classifies zlib statuses `Z_OK`, `Z_STREAM_END`, and `Z_NEED_DICT`
as non-errors and every other status as an error. Separate switch cases recover
the native VC6 decrement-and-branch dispatch exactly.

The VC6 `/O2 /GB /MD` function is an exact 11-instruction match.

The native audit retains this isolated scratch as the canonical baseline, then
validates the helper again under the island's shared `/GX /MD` profile as the
second member of `grim-jaz-decode-island`.
