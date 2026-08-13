# `grim_jpeg_start_pass_one_quantizer`

Native target: `grim.dll` at `0x10033da6`, 202 bytes and 72 normalized
instructions.

The pinned DirectX 8.1 archive identifies this body in `jquant1.obj` and
records `@comp.id=0x001d23da` (product 29, build 9178). The canonical scratch
uses that original member directly and is byte-exact with all nine
archive-local references resolved.

The earlier faithful IJG 6a source reconstruction reproduced 71 of 72 aligned
instructions under the 13.10.3077 surrogate. The exact Windows XP DDK
13.00.9176/9178 profile emits the native `and` clear before the method-pointer
store and reproduces all 202 bytes and 72 instructions without a scheduling
constraint.
