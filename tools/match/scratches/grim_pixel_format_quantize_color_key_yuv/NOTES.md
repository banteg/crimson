# `grim_pixel_format_quantize_color_key_yuv`

Native target: `grim.dll` at `0x10016c3b`, one byte.

The complete function is a single `ret`. It is the shared no-op color-key
quantizer installed in the UYVY and YUY2 pixel-format tables. The mapped
signature takes the pixel-format object in `ECX`, represented here with a
one-argument `__fastcall` function.
