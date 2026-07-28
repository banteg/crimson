# grim_zlib_decompress_alloc

Native target: `grim.dll` at `0x1000a840..0x1000a87c` (60 bytes).

This `GrimJazDecodeScope` method allocates the requested output buffer with
`operator new`, initializes a separate available-size local, calls the zlib
1.1.3 `uncompress` implementation embedded in the confirmed `d3dx8.lib`, and
returns the inverse of `grim_zlib_status_is_error`.

Declaring the available-size local after the allocation preserves the original
value across `operator new` in `esi`, reproducing the native VC6 lifetime and
stack layout. The `/O2 /GB /MD` method is an exact 22-instruction match with
all three references resolved.

The native audit retains this isolated scratch as the canonical baseline, then
validates the method again under the island's shared `/GX /MD` profile as the
third member of `grim-jaz-decode-island`.
