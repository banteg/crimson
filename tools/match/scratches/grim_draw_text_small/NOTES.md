# grim_draw_text_small

## Plausibility pass (2026-09-27)

The font UV table is the `GrimUV[256]` array that `grim_state_init` fills, read through `.u` and `.v`, instead of two float arrays indexed by `glyph * 2`. The `uv1_raw` intermediate stays: it rounds the sum to float before the final subtract. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

Draws newline-delimited text from the `GRIM_Font2` atlas. The renderer snaps
the origin to integer coordinates, temporarily forces texture filtering mode
1, derives each glyph's UV rectangle from the atlas tables, batches 16-pixel
high quads, and restores the previous filter mode. The raw and inset endpoint
values preserve the two-stage UV construction visible in the native x87 code.

Matches all 153 native instructions and all 18 masked references.
