# `grim_jpeg_start_pass_two_quantizer`

Native target: `grim.dll` at `0x100332e1`, 258 bytes and 92 normalized
instructions.

The recovered IJG 6a initializer selects prescan or second-pass methods,
validates the colormap, allocates and clears Floyd-Steinberg state, initializes
the error limiter, and clears all 32 histogram planes when required. All eight
archive-local references resolve and the candidate has the exact instruction
count at 97.83%.

Two equivalent byte clears are the complete residual: build 9178 emits `and`
for `on_odd_row` and `needs_zeroed`, while CL 13.10.3077 emits `mov`. The
official source remains `semantic-complete` with a `compiler` residual; it is
not rewritten as bitwise self-mutation merely to select those opcodes.
