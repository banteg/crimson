# `grim_pixel_format_quantize_color_key_yuv`

Native target: `grim.dll` at `0x10016c3b` (1 byte).

UYVY and YUY2 share this empty specialization of the pixel-format color-key
quantization slot. Their packed YUV path does not rewrite the stored RGBA key.
