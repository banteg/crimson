# State machine

**Status:** Draft

This page tracks the main runtime state flags in `crimsonland.exe` and the
known state ids. Names are inferred from call sites and screen behavior.

## Key globals

| Symbol | Meaning (inferred) | Evidence |
| --- | --- | --- |
| `DAT_00487270` | current state id | set in `FUN_004461c0`, checked throughout render/update loops |
| `DAT_0048726c` | previous state id | set in `FUN_004461c0` before changing state |
| `DAT_00487274` | pending transition target | used by `ui_elements_update_and_render` to switch states |
| `DAT_00487248` | transition timeline | incremented/decremented in `ui_elements_update_and_render` |
| `DAT_0048724c` | transition direction flag | `ui_elements_update_and_render` negates timeline when 0 |
| `DAT_00487278` | transition alpha | computed in `FUN_00405960` from timeline |
| `DAT_00487240` | render gating | dispatcher uses it to choose terrain-only vs full pass |
| `DAT_004808b8` | pause toggle | checked in the main frame loop |
| `DAT_0048700d` | demo/attract gating | disables HUD and alters update behavior |

## Known state ids

| Id | Label (inferred) | Evidence |
| --- | --- | --- |
| `0` | main menu / root UI | `FUN_004461c0(0)`, load step sets `DAT_00487270 = 0` |
| `6` | perk selection | direct `FUN_004461c0(6)` when perk prompt is accepted |
| `7` | game over / high score entry | `FUN_0040ffc0` checks `DAT_00487270 == 7` |
| `8` | quest results | `quest_results_screen_update` checks `DAT_00487270 == 8` |
| `9` | gameplay | `FUN_0040aab0` runs creature/projectile/player updates only when 9 |
| `0xc` | quest failed | `FUN_004107e0` checks `DAT_00487270 == 0xc` |
| `0x12` | Typ-o-Shooter gameplay | `FUN_004457c0` updates when `DAT_00487270 == 0x12` |
| `0x16` | modal/plugin flow (unknown) | `FUN_0040b630` special-cases `DAT_00487270 == 0x16` |
| `10` | unknown (menu related) | `ui_elements_update_and_render` sets `DAT_0047ea50` when 10 |
| `0x14` | unknown (modal/gated) | only appears in render gating and as a transition target |

## Transition rules

- `ui_elements_update_and_render` updates `DAT_00487248`. When it drops below 0,
  it calls `FUN_004461c0(DAT_00487274)` and then sets `DAT_00487274 = 0x19`.
- Menu buttons set `DAT_00487274 = 9` (Survival/Rush) or `DAT_00487274 = 0x12`
  (Typ-o-Shooter), then clear `DAT_0048724c` to start the transition.
- Quest completion sets `DAT_00487274 = 8` after the final spawn wave.
- Player death sets `DAT_00487274 = 7` for non-quest modes or `0xc` for quests.
- Perk selection uses a direct `FUN_004461c0(6)` instead of a queued transition.

## Notes

- `0x19` is used as an idle sentinel for `DAT_00487274`, not as a real state id.
- The exact meanings of states `10`, `0x14`, and `0x16` still need confirmation.
