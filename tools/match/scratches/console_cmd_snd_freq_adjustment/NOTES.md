# console_cmd_snd_freq_adjustment

Native target: `crimsonland.exe` at `0x0042a930` (58 bytes).

The command flips the byte at config offset `0x460` and reports the resulting
state. This identifies the previously reserved field as
`sound_frequency_adjustment` while preserving the full `crimson_cfg_t` layout.

The boolean temporary reproduces the native `sete`, store, and branch sequence.
The source matches all 16 instructions, full prefix, with all eight references
aligned.
