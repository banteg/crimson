# `grim_jpeg_create_color_index`

Native target: `grim.dll` at `0x100336fd`, 299 bytes and 102 normalized
instructions.

The recovered IJG 6a routine allocates and fills the component color-index
tables, including the ordered-dither padding and range-limit adjustment. The
local profile reproduces 101 of 102 aligned instructions. Its only residual is
an equivalent byte clear: the provider object emits `and byte ptr [...], 0`,
where the available compiler emits `mov byte ptr [...], 0`.

The source is retained as `semantic-complete` with a `compiler` residual. No
type distortion or volatile write is used to force the provider's instruction
selection.
