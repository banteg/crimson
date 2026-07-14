# console_cmd_load_texture

Native target: `crimsonland.exe` at `0x0042a780` (60 bytes).

The handler requires an argument count of two, prints usage otherwise, then
passes `console_cmd_arg_get(2)` as both texture name and path. This is a native
off-by-one bug: the exact argument accessor accepts only positive indices below
`argc`, so index two resolves to the shared empty string when `argc == 2`.

Preserving the bug matches all 19 instructions, full prefix, with all seven
references aligned.
