# mod_api_sfx_play_sample

Native target: `crimsonland.exe` at `0x40e570` (49 bytes).

The one-dimensional SDK pan value becomes a native two-float position:
`{pan * 512.0f, 0.0f}`. The wrapper forwards that position and the requested
volume to `sfx_play_panned`. Natural source matches all 14 instructions and
both references exactly.
