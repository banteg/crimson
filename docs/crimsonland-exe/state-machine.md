---
tags:
  - status-draft
---

# State machine

**Status:** Draft

This page tracks the main runtime state flags in `crimsonland.exe` and the
known state ids. Names are inferred from call sites and screen behavior.

## Key globals

| Symbol | Meaning (inferred) | Evidence |
| --- | --- | --- |
| `game_state_id` (`DAT_00487270`) | current state id | set in `game_state_set` (`FUN_004461c0`), checked throughout render/update loops |
| `game_state_prev` (`DAT_0048726c`) | previous state id | set in `game_state_set` (`FUN_004461c0`) before changing state |
| `game_state_pending` (`DAT_00487274`) | pending transition target | used by `ui_elements_update_and_render` to switch states |
| `ui_elements_timeline` (`DAT_00487248`) | transition timeline | incremented/decremented in `ui_elements_update_and_render` |
| `ui_transition_direction` (`DAT_0048724c`) | transition direction flag | `ui_elements_update_and_render` negates timeline when 0 |
| `ui_transition_alpha` (`DAT_00487278`) | transition alpha | computed in `gameplay_render_world` (`FUN_00405960`) from timeline |
| `render_pass_mode` (`DAT_00487240`) | render gating | dispatcher uses it to choose terrain-only vs full pass |
| `game_paused_flag` (`DAT_004808b8`) | pause toggle | checked in the main frame loop |
| `demo_mode_active` (`DAT_0048700d`) | demo/attract gating | disables HUD and alters update behavior |

## Known state ids

| Id | Label (inferred) | Evidence |
| --- | --- | --- |
| `0` | main menu / root UI | `game_state_set` (`FUN_004461c0(0)`), load step sets `game_state_id` (`DAT_00487270`) = `0` |
| `5` | pause (console/mod pause) | `mod_api_cl_enter_menu` (`FUN_0040e690`) sets `game_state_pending` (`DAT_00487274`) = `5` on `game_pause` |
| `6` | perk selection | direct `game_state_set` (`FUN_004461c0(6)`) when perk prompt is accepted |
| `7` | game over / high score entry | `game_over_screen_update` checks `game_state_id` (`DAT_00487270`) == `7` |
| `8` | quest results | `quest_results_screen_update` checks `game_state_id` (`DAT_00487270`) == `8` |
| `9` | gameplay | `gameplay_update_and_render` runs creature/projectile/player updates only when 9 |
| `0xc` | quest failed | `quest_failed_screen_update` checks `game_state_id` (`DAT_00487270`) == `0xc` |
| `0x12` | Typ-o-Shooter gameplay | `survival_gameplay_update_and_render` (`FUN_004457c0`) updates when `game_state_id` (`DAT_00487270`) == `0x12` |
| `0x16` | modal/plugin flow | `FUN_0040b630` drives a DLL-backed interface (`plugin_interface_ptr` (`DAT_004824d4`)) when `0x16` |
| `0x14` | modal fallback / return from plugin | queued as transition target when the plugin is missing or ends in `FUN_0040b630` |
| `10` | unknown (menu-related) | `ui_elements_update_and_render` sets `DAT_0047ea50` when 10 |

## Transition rules

- `ui_elements_update_and_render` updates `ui_elements_timeline` (`DAT_00487248`). When it drops below `0`,
  it calls `game_state_set` (`FUN_004461c0`) with `game_state_pending` (`DAT_00487274`) and then sets `game_state_pending` (`DAT_00487274`) = `0x19`.

- Menu buttons set `game_state_pending` (`DAT_00487274`) = `9` (Survival/Rush) or `game_state_pending` (`DAT_00487274`) = `0x12`
  (Typ-o-Shooter), then clear `ui_transition_direction` (`DAT_0048724c`) to start the transition.

- Quest completion sets `game_state_pending` (`DAT_00487274`) = `8` after the final spawn wave.
- Player death sets `game_state_pending` (`DAT_00487274`) = `7` for non-quest modes or `0xc` for quests.
- Perk selection uses a direct `game_state_set` (`FUN_004461c0(6)`) instead of a queued transition.
- `game_pause` (console/mod command) sets `game_state_pending` (`DAT_00487274`) = `5`.

## Notes

- `0x19` is used as an idle sentinel for `game_state_pending` (`DAT_00487274`), not as a real state id.
- The exact meaning of state `10` still needs confirmation.
