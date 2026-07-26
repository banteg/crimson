# `config_init_defaults`

Native target: `crimsonland.exe` at `0x004028f0` (734 bytes).

Live Binary Ninja evidence recovers the persistent configuration defaults,
eight saved-name slots, display and audio defaults, both players' complete
keyboard/joystick bindings, and the two direction-arrow flags.

The two contiguous 0x40-byte binding spans are now represented as
`player_input_config_t input_config[2]`. This names all 13 active bindings and
the three unbound tail slots per player without changing their persisted
layout.

The four movement selectors at `0x1c` and four aim selectors at `0x44` are
likewise recovered as per-player arrays. This agrees with the native indexed
controls-menu accesses and the fixed `crimson.cfg` parser, replacing the old
single-player fields plus byte-gap presentation.

The function is `void`. Its only discovered consumer is the static-initializer
thunk recorded at `0x0047100c`, and the apparent `0x17e` return is just EAX
residue from the repeated unbound-key assignments.

VC6 `/O2 /GB /Oy-` produces 86.62% with 140 native and 144 candidate
normalized instructions and 80/0/0 reference agreement. This function-local
frame-pointer override improves the former `/O2 /GB` result by 65.19
fuzzy-weighted bytes (77.74% to 86.62%) and resolves both apparent reference
mismatches. A full backend and optimizer matrix confirmed that ordinary
`/O2 /GB` remains at 77.74%, `/G6` falls to 72.08%, and the 6.5pp and MSVC 7
backends are materially worse.

The residual is register allocation around the saved-name loop: native keeps
the slot index in `EBX`, the scaled order-array offset in `EBP`, and one name
cursor on the stack. The natural reconstruction assigns those lifetimes
differently, which also changes the scheduling of later constant stores. The
evidence-backed frame-pointer profile is retained instead of introducing
source-shaped register coercion.

Live Wave 4 reinspection confirmed the two formerly mismatched stores are
the correctly laid-out `config_blob.windowed` (`0x48050c`) and
`config_blob.game_mode` (`0x480360`) fields. Replacing them with the overlapping
Binary Ninja symbol aliases leaves the instruction score unchanged and worsens
reference agreement to 63/0/4, proving that the struct-field form is the honest
candidate. Recovery is therefore semantic-complete; `/Oy-` now aligns those
stores cleanly at 80/0/0. The scratch consequently carries only a `compiler`
residual, with no independent source-reference debt and no alias masking.
