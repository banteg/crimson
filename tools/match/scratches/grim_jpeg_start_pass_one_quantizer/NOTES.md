# `grim_jpeg_start_pass_one_quantizer`

Native target: `grim.dll` at `0x10033da6`, 202 bytes and 72 normalized
instructions.

The recovered IJG 6a pass initializer selects the non-dithered, ordered, or
Floyd-Steinberg quantizer, creates the color index or ordered-dither tables as
needed, clears the FS workspaces, and resets row parity. All nine archive-local
references resolve.

The local profile reproduces 71 of 72 aligned instructions. Build 9178 clears
the byte-sized odd-row flag with `and` before publishing the method pointer;
the available compiler schedules an equivalent `mov` clear after that store.
The source is retained as `semantic-complete` with a `compiler` residual and no
volatile scheduling constraint.
