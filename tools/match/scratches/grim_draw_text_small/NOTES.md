# grim_draw_text_small

Draws newline-delimited text from the `GRIM_Font2` atlas. The renderer snaps
the origin to integer coordinates, temporarily forces texture filtering mode
1, derives each glyph's UV rectangle from the atlas tables, batches 16-pixel
high quads, and restores the previous filter mode. The raw and inset endpoint
values preserve the two-stage UV construction visible in the native x87 code.

Matches all 153 native instructions and all 18 masked references.
