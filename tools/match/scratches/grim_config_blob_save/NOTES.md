# grim_config_blob_save

`grim_config_blob_save` at `0x100019f0` is the legacy Win32-launcher settings
writer. It opens `crimson.cfg` in binary-write mode, writes the complete
`0x480`-byte `grim_config_blob` when the file opens successfully, closes it,
and returns true even when the open fails.

The natural MSVC 6.5 `/O2 /GB` reconstruction matches all 19 native
instructions, all 59 bytes, and all six references. This function remains
`platform-replaced` for port ownership, but its exact object is included in
the recovered Grim platform provider used by structural native linking.
