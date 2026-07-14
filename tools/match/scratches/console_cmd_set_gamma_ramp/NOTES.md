# console_cmd_set_gamma_ramp

Native target: `crimsonland.exe` at `0x0042c3d0` (116 bytes).

The command requires one scalar argument and prints two help lines otherwise.
It parses with the CRT `atof`-style double routine, narrows once to float,
passes that float in a 16-byte `grim_config_value_t` to Grim2D config slot
`0x1c`, and promotes the same stored float for the confirmation message.

Only the first word of the config record is initialized. MSVC naturally reuses
the two prior call arguments plus eight newly reserved bytes for its remaining
three words, explaining the compact native stack schedule without manufactured
instructions.
