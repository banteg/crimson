# console_cmd_set_resource_paq

Native target: `crimsonland.exe` at `0x0042a7c0` (158 bytes).

The command validates one resource-pack argument by opening it in binary mode.
Missing files are reported without changing configuration; accepted files are
closed, passed as the string-valued Grim2D configuration variable `16`, and
reported to the console.

The recovered `grim_config_value_t` converting constructor reproduces the
native 16-byte by-value virtual call. The source matches all 51 instructions,
full prefix, with all eighteen references aligned.
