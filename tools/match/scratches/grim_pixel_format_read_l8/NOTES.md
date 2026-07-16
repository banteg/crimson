# `grim_pixel_format_read_l8`

Native target: `grim.dll` at `0x10019bd3` (110 bytes).

This L8 vtable reader walks one addressed row of unsigned luminance bytes,
expands each sample through the native `1/255` scale into equal RGB floats,
sets alpha to one, and applies the active color key to the completed row.
