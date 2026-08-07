# `grim_jpeg_idct_islow`

Native target: `grim.dll` at `0x10044e50`, 1,616 bytes and 470 normalized
instructions.

The implementation is IJG libjpeg 6a's stock slow integer inverse DCT. Native
code sign-extends the low 16 bits immediately before fixed-constant
multiplications while retaining the 32-bit inverse-DCT multiplier table. This
is the exact shape selected by IJG's documented `SHORTxLCONST_32` path for
Microsoft C 6.0; changing `MULTIPLIER` to `short` instead changes table layout
and is not equivalent.

MSVC 6.0, 6.5, and 6.6 all reproduce the same target with `/O2 /Ob2 /G6` and
`SHORTxLCONST_32`. The retained default compiler matches all 1,616 bytes and
all 470 normalized instructions exactly, with no relocations to audit.
