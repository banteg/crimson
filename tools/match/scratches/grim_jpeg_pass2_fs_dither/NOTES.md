# `grim_jpeg_pass2_fs_dither`

Native target: `grim.dll` at `0x10032fc1`, 622 bytes and 206 normalized
instructions.

The pinned DirectX 8.1 archive identifies this body in `jquant2.obj` and
records `@comp.id=0x001d23da` (product 29, build 9178). The canonical scratch
uses that original member directly and is byte-exact with its archive-local
inverse-map reference resolved.

The earlier faithful IJG 6a source reconstruction reached 99.03% under the
13.10.3077 surrogate. The exact Windows XP DDK 13.00.9176/9178 profile selects
the native `and` clear and schedule and reproduces all 622 bytes and 206
instructions with no source shaping.
