# `grim_jpeg_idct_4x4`

Native target: `grim.dll` at `0x10045d90`, 1,019 bytes and 310 normalized
instructions.

This is IJG libjpeg 6a's stock 4x4 reduced inverse DCT compiled through the
Microsoft-specific `SHORTxLCONST_32` fixed-point multiply path. The target's
16-bit sign extensions before constant multiplies prove that configuration;
the quantization multiplier table remains 32-bit.

MSVC 6.5 with `/O2 /Ob2 /G6` matches all 1,019 bytes and all 310 normalized
instructions exactly, with no relocations to audit.
