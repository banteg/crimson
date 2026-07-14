# `input_aim_pov_left_active`

Exact 32-byte, 10-instruction match with MSVC 6.5 `/O2 /GB`; both masked
references align (`grim_interface_ptr` and `config_blob.aim_pov_left`).

The helper asks Grim2D for joystick zero's current POV value and compares it
with the aim-left binding stored at config offset `0x1b4`. The exact match also
recovers the direct boolean return shape: VC6 emits the virtual call followed
by `cmp`/`sete` without a branch.
