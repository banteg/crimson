# `dx_version_pack_4x16`

Exact 49-byte, 13-instruction match with MSVC 6.5 `/O2 /GB`; the function is
pure and has no masked references.

The four parameters are genuinely `unsigned short`, not the decompilers'
32-bit integer guesses. That signature makes VC6 emit the native `and 0xffff`
for every stack argument before packing `{major, minor}` into the high dword
and `{patch_major, patch_minor}` into the low dword. With 32-bit parameters,
VC6 proves two pre-shift masks redundant and cannot match.

A small 64-bit/word union expresses the native return ABI directly: the packed
value leaves in `EDX:EAX`, with no runtime helper or stack temporary.
