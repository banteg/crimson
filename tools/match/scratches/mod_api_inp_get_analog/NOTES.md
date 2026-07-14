# mod_api_inp_get_analog

Native target: `crimsonland.exe` at `0x40e620` (52 bytes).

Keys `0x163` and `0x164` expose the UI mouse X/Y globals directly. Every other
key is forwarded to Grim config-float slot lookup. The recovered virtual method
matches all 14 instructions and all 3 references exactly.
