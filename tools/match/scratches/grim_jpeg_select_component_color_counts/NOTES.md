# `grim_jpeg_select_component_color_counts`

Native target: `grim.dll` at `0x10033505`, 203 bytes and 83 normalized
instructions.

The recovered IJG 6a policy distributes the requested palette across the
output components, using the archive-confirmed RGB preference order. The local
compiler reproduces 82 of 83 aligned instructions with its sole difference in
the independent local initialization schedule: build 9178 clears the
byte-sized `changed` flag before the integer loop index, while the available
profile clears and tests the index first. All references resolve.

The source is retained as `semantic-complete` with a `compiler` residual. It
contains no volatile store forcing or artificial dependency to choose between
the two equivalent schedules.
