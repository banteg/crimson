# grim_config_blob_load

`grim_config_blob_load` at `0x10001a30` is the legacy Win32-launcher settings
reader. It creates a missing `crimson.cfg` through `grim_config_blob_save`,
reopens it, rejects a second open failure, and replaces files whose size is
not exactly `0x480` bytes. Valid files are rewound and read into the complete
`grim_config_blob` before closing.

The natural MSVC 6.5 `/O2 /GB` reconstruction matches all 56 native
instructions, all 151 bytes, and all 13 references. This function remains
`platform-replaced` for port ownership, but its exact object is included in
the recovered Grim platform provider used by structural native linking.
