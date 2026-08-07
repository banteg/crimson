# `grim_jpeg_init_one_pass_quantizer`

Native target: `grim.dll` at `0x10044210`, 571 bytes and 196 normalized
instructions.

The implementation is IJG libjpeg 6a's stock `jinit_1pass_quantizer` body.
Native disassembly preserves calls to `select_ncolors` at `0x10044450` and
`create_colorindex` at `0x10044540`, while inlining `create_colormap` and the
small Floyd-Steinberg workspace allocator into the initializer. The two
out-of-line helpers are independently recovered targets, so these are proven
translation-unit boundaries rather than speculative source changes.

MSVC 6.5 with `/O2 /Ob2 /G6 /W3 /MD` otherwise inlines all three helpers and
produces 268 instructions. `/Ob1`, `/Ob0`, and size-oriented optimization keep
the whole helper layer out of line and produce only 50-52 instructions. Other
available VC6 and VC7 compiler profiles do not reproduce the selective native
boundary.

`AUTO_INLINE_OFF=select_ncolors,create_colorindex` stages MSVC auto-inline
pragmas around only those two definitions. The canonical IJG source remains
pristine. With those native-proven boundaries, the stock source matches all
571 bytes, all 196 normalized instructions, and all five relocations exactly.
