# `grim_jpeg_select_component_color_counts`

Native target: `grim.dll` at `0x10033505`, 203 bytes and 83 normalized
instructions.

The pinned DirectX 8.1 archive identifies this body in `jquant1.obj` and
records `@comp.id=0x001d23da` (product 29, build 9178). The canonical scratch
uses that original member directly and is byte-exact with its RGB preference
table reference resolved.

The earlier faithful IJG 6a source reconstruction reproduced 82 of 83 aligned
instructions under the 13.10.3077 surrogate. The exact Windows XP DDK
13.00.9176/9178 profile selects the native local-initialization schedule and
reproduces all 203 bytes and 83 instructions without a volatile or artificial
dependency.
