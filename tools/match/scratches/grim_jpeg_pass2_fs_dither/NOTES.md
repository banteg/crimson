# `grim_jpeg_pass2_fs_dither`

Native target: `grim.dll` at `0x10032fc1`, 622 bytes and 206 normalized
instructions.

The recovered IJG 6a mapper alternates scan direction, applies the error-limit
table, uses the inverse-colormap cache, and propagates all three components'
Floyd-Steinberg errors. Its archive-local inverse-map reference resolves and
the available compiler emits the exact 206-instruction count at 99.03%.

The only differing region is the independent odd-row byte clear: build 9178
selects `and` and schedules it before the right-to-left pointer adjustment,
while CL 13.10.3077 selects `mov` and schedules it after that adjustment. The
official source order is retained as `semantic-complete` with a `compiler`
residual; no volatile store or artificial dependency forces the provider's
schedule.
