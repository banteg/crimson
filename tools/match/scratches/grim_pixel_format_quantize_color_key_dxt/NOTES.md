# `grim_pixel_format_quantize_color_key_dxt`

Native target: `grim.dll` at `0x1001af00` (257 bytes).

This DXT vtable specialization snaps the stored color key to the codec's native
5:6:5 RGB lattice. DXT2/DXT3 use four-bit explicit alpha; the other DXT formats
use eight-bit alpha. The method stores both the alpha maximum and its reciprocal
for later encode/decode comparisons.

The native function contains an inlined 32-bit x87 float-to-int primitive for
each channel (`fstp`/`fld`/`fistp dword`). Portable VC6 C++ instead calls
`_ftol`; `/QIfist` emits a 64-bit `fistp` and still does not match. The scratch
therefore keeps the conversion helper in policy-valid C++ and records this as an
honest compiler-boundary WIP rather than embedding prohibited inline assembly.
