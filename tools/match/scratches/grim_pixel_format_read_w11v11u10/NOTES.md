# `grim_pixel_format_read_w11v11u10`

Native target: `grim.dll` at `0x1001a031` (186 bytes).

This W11V11U10 vtable reader sign-extends the packed 10-bit U component and
11-bit V/W components, normalizes them through `1/512` and `1/1024`, emits one
for alpha, and applies the active color key to the completed row.

The explicit `short` shifts recover the native packed-field sign extension
without implementation-defined C++ bitfields. Both the VC6.5 processor-pack
and MSVC 7.0 profiles reproduce all 63 instructions; MSVC 7.0 is recorded
because the immediately adjacent A2W10V10U10 method distinguishes that shared
codegen profile.
