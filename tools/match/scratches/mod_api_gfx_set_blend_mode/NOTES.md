# mod_api_gfx_set_blend_mode

Native target: `crimsonland.exe` at `0x40e3a0` (49 bytes).

The wrapper writes destination blend mode to Grim config slot `0x14` first,
then source blend mode to slot `0x13`. Its two 16-byte `grim_config_value_t`
temporaries and both virtual calls match all 17 native instructions exactly.
