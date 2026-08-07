# `grim_jpeg_idct_2x2`

Native target: `grim.dll` at `0x10046190`, 556 bytes and 173 normalized
instructions.

This is IJG libjpeg 6a's stock 2x2 reduced inverse DCT compiled through the
Microsoft-specific `SHORTxLCONST_32` fixed-point multiply path. It shares the
same native-proven 16-bit constant-multiply configuration as the slow and 4x4
inverse DCTs without changing the 32-bit quantization table layout.

MSVC 6.5 with `/O2 /Ob2 /G6` matches all 556 bytes and all 173 normalized
instructions exactly, with no relocations to audit.
