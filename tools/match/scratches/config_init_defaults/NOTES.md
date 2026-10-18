# `config_init_defaults`

Native target: `crimsonland.exe` at `0x004028f0` (734 bytes); 1.9.8 at
`0x00402830` (704 bytes).

Live Binary Ninja evidence recovers the persistent configuration defaults,
eight saved-name slots, display and audio defaults, both players' complete
keyboard/joystick bindings, and the two direction-arrow flags. The bindings are
`player_input_config_t input_config[2]` (13 active bindings and three unbound
tail slots per player); the movement and aim selectors are per-player arrays.

The function is `void`. Its only discovered consumer is the static-initializer
thunk at `0x0047100c`; the apparent `0x17e` return is EAX residue from the
repeated unbound-key assignments.

The body is shared with Grim's byte-identical `grim_config_defaults_init` as
the inline member `crimson_cfg_cpp_t::set_defaults()`
(`tools/match/include/crimson_config_defaults_impl.h`), called on `config_blob`.
1.9.93 is exact (734/734 bytes, 140/140, references 83/0/0) with stock
`/O2 /GB /W3 /GR-` and a plain indexed saved-name loop. Why `this` matters, the
1.9.8 register-allocation residual (86.61%, 127/127) and the `ui_info_texts`
guard are in `../grim_config_defaults_init/NOTES.md`. Earlier cursor-shaped
reconstructions and their sweeps are in git history.

## 1.9.8 match (2026-10-19)

Both builds match: 1.9.93 stays exact; 1.9.8 is 127/127 with references
84/0/0 and one encoded byte left, the SIB of the default-name copy store
(native `[eax+esi]`, 9044 `[esi+eax]`; see
`../highscore_sync_worker/NOTES.md`). The register swap came from colouring
priority (`scripts/c2/priority_trace.py --build 1.9.8`): the 16-bit arrow-flag
store `*(unsigned short *)direction_arrow_flags = 0x101` shared its immediate
with `key_pick_perk = 0x101`, adding a candidate range to block 1 and raising
the delta's priority above the source cursor's. `memset(direction_arrow_flags,
1, 2)` emits the same `mov word` with a different immediate, so the cursor
colours `eax` first. The defaults also move `detail_preset`, the POV angles,
the reserved word and the screen size to config_sync_from_grim's store order,
and a guard stores `ui_info_texts` directly under 1.9.8.
