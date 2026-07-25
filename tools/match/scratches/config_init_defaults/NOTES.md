# `config_init_defaults`

Native target: `crimsonland.exe` at `0x004028f0` (734 bytes).

Live Binary Ninja evidence recovers the persistent configuration defaults,
eight saved-name slots, display and audio defaults, both players' complete
keyboard/joystick bindings, and the two direction-arrow flags.

The two contiguous 0x40-byte binding spans are now represented as
`player_input_config_t input_config[2]`. This names all 13 active bindings and
the three unbound tail slots per player without changing their persisted
layout.

The function is `void`. Its only discovered consumer is the static-initializer
thunk recorded at `0x0047100c`, and the apparent `0x17e` return is just EAX
residue from the repeated unbound-key assignments.

VC6 `/O2 /GB` produces 77.74% with 140 native and 143 candidate normalized
instructions and 65/0/2 reference agreement. The residual is register
allocation around the saved-name loop: native keeps the slot index in `EBX`,
the scaled order-array offset in `EBP`, and one name cursor on the stack. The
natural reconstruction instead keeps constant one in `EBX`, advances an
absolute order pointer in `EBP`, and spills the slot index, which also changes
the scheduling of later constant stores. C mode, the `msvc6.5pp` and MSVC 7
backends, and `/G6` were checked and are materially worse. The semantic WIP is
retained instead of introducing source-shaped register coercion.
