# `grim_jpeg_start_pass_two_quantizer`

Native target: `grim.dll` at `0x100332e1`, 258 bytes and 92 normalized
instructions.

The pinned DirectX 8.1 archive identifies this body in `jquant2.obj` and
records `@comp.id=0x001d23da` (product 29, build 9178). The canonical scratch
uses that original member directly and is byte-exact with all eight
archive-local references resolved.

The earlier faithful IJG 6a source reconstruction reached 97.83% under the
13.10.3077 surrogate. The exact Windows XP DDK 13.00.9176/9178 profile emits
the native `and` clears for `on_odd_row` and `needs_zeroed` and reproduces all
258 bytes and 92 instructions without bitwise source mutation.
