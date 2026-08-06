# `png_read_data`

The full 40-byte native body is a unique exact match for
`obj\i386\pngrio.obj:?png_read_data@D3DX@@YAXPAUpng_struct_def@1@PAEI@Z` in
the pinned DirectX 8.1 archive. It dispatches the configured read callback or
raises libpng's `Call to NULL read function` error.

The original IDA extent stopped at `0x100204a1`, omitting the caller cleanup
and return. The curated manifest end at `0x100204a4` now restores those three
instructions for every matcher consumer.
