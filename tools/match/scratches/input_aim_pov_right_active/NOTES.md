# `input_aim_pov_right_active`

Exact 32-byte, 10-instruction match with MSVC 6.5 `/O2 /GB`; both masked
references align (`grim_interface_ptr` and `config_blob.aim_pov_right`).

This is the adjacent mirror of `input_aim_pov_left_active`: it queries joystick
zero's POV and compares it with the aim-right binding at config offset `0x1b0`.
The direct comparison return reproduces the native `cmp`/`sete` tail exactly.
