---
tags:
  - status-analysis
---

# Local multiplayer controls (native evidence)

This note consolidates the controls/multiplayer evidence used by the rewrite.

## Config storage and player blocks

- `crimson.cfg` is fixed-size `0x480` bytes and rewritten as a whole struct.
  - Ref: `docs/formats/crimson-cfg.md`
- Keybind blocks: `crimson_cfg_t.input_config[10]` (`player_input_config_t`,
  `third_party/headers/crimsonland_types.h`) holds ten `0x40`-byte slots
  (`13 dwords + 3 dwords padding`) starting at `0x1c8`:
  - P1: slot 0 at `0x1c8`
  - P2: slot 1 at `0x208`
  - Slots 2..9 occupy `0x248..0x447`; the native build copies only slots 0 and 1,
    and the ports use slots 2 and 3 for P3/P4.
  - Ref: `docs/formats/crimson-cfg.md`

## Control mode IDs and labels

- Aim-scheme labels come from `input_configure_for_label` (`0x00447c90`):
  - `0 Mouse`, `1 Keyboard`, `2 Joystick`, `3 Mouse relative`, `4 Dual Action Pad`, `5 Computer`
- Move-scheme labels come from `input_scheme_label` (`0x00447cf0`):
  - `1 Relative`, `2 Static`, `3 Dual Action Pad`, `4 Mouse point&click`, `5 Computer`
- Ref: `docs/crimsonland-exe/ui.md`

## Per-scheme semantics (evidence anchors)

- `player_state_t.input` (`player_input_t` at `+0x32c`) carries explicit per-player bindings:
  - aim keys (`+0x348/+0x34c`)
  - aim axes (`+0x350/+0x354`)
  - move axes (`+0x358/+0x35c`)
- Explicit branch evidence:
  - movement scheme `== 3` reads move axes
  - aim scheme `== 4` reads aim axes
- Ref: `docs/structs/player.md`

## Controls menu + rebind runtime

- Controls dropdown list widgets:
  - `controls_move_method_list` (`0x004d7638`)
  - `controls_player_profile_list` (`0x004d7660`)
  - `controls_aim_method_list` (`0x004d76a8`)
- Rebind table + menu items:
  - `controls_rebind_items` (`0x004d7898`)
  - `controls_key_pick_perk_item` (`0x004d7968`)
  - `controls_key_reload_item` (`0x004d7978`)
- Axis-capture peaks + threshold path:
  - `controls_rebind_axis_peak_abs_*` (`0x004d79e4..0x004d79f8`)
  - compared against `0.5` assignment threshold.
- Ref: `docs/crimsonland-exe/ui.md`
