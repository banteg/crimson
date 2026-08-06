# `grim_jpeg_quantize_fs_dither`

Native target: `grim.dll` at `0x10033bec`, 388 bytes and 133 normalized
instructions.

This is the official IJG 6a Floyd-Steinberg one-pass quantizer: it alternates
scan direction, propagates scaled error across the component workspaces, clamps
samples through the range-limit table, and writes the mapped palette index.
The archive-local zeroing helper resolves exactly.

The available profile emits 132 instructions and reaches 94.34%. The remaining
differences are register choice, value lifetime, and nearby scheduling across
the inner component loop; no behavior or reference is missing. The source is
therefore `semantic-complete` with a `compiler` residual, without artificial
register constraints or dead dependencies.
