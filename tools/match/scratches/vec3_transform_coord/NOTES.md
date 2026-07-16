# `vec3_transform_coord`

Native target: `crimsonland.exe` at `0x0045eac0` (139 bytes).

This is the 3DNow! implementation behind the vector/matrix dispatch surface.
It broadcasts input X, Y, and Z into packed pairs, evaluates matrix columns
`XY` and `ZW`, refines a packed reciprocal of W with `pfrcpit1` and
`pfrcpit2`, multiplies XYZ by that reciprocal, and returns the destination.
The native function uses stdcall and brackets the MMX/3DNow! work with
`femms`.

The Microsoft 3DNow! intrinsics express the native operations directly and
recover its complete algorithm. The strongest available candidate is MSVC 7.0
with `/O1 /Oi /G6`: it emits 54 normalized instructions against 37 native and
scores 17.58%, with no reference operands.

The residual identifies a likely hand-authored backend. Native uses fixed MMX
registers and memory-form packed arithmetic without a frame; every available
MSVC intrinsic profile aligns the stack and materializes several matrix loads
and value copies. The scratch therefore remains WIP. No inline assembly,
naked function, volatile state, dummy dependency, or forced register construct
is used to imitate that schedule.
