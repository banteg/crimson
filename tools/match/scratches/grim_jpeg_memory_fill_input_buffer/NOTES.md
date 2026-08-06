# `grim_jpeg_memory_fill_input_buffer`

Native target: `grim.dll` at `0x1003aa20`, 158 bytes.

The recovered callback copies at most 4 KiB from the caller-owned input,
reports an empty first buffer through IJG's error path, and otherwise supplies
the standard synthetic EOI marker at end of input. This scratch reuses the
provider's exact IJG 6a source and compiler profile.
