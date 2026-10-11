---
tags:
  - status-analysis
---

# State machine
This page tracks the main runtime state flags in `crimsonland.exe` and how
state transitions happen. The id-by-id table is the
[State id glossary](state-ids.md).

## Key globals

| Symbol | Meaning | Evidence |
| --- | --- | --- |
| `game_state_id` (`0x00487270`) | current state id | set in `game_state_set` (`0x004461c0`), checked throughout render/update loops |
| `game_state_prev` (`0x0048726c`) | previous state id | set in `game_state_set` (`0x004461c0`) before changing state |
| `game_state_pending` (`0x00487274`) | pending transition target | used by `ui_elements_update_and_render` to switch states |
| `ui_elements_timeline` (`0x00487248`) | transition timeline | incremented/decremented in `ui_elements_update_and_render` |
| `ui_transition_direction` (`0x0048724c`) | transition direction flag | `ui_elements_update_and_render` negates timeline when 0 |
| `ui_transition_alpha` (`0x00487278`) | transition alpha | computed in `gameplay_render_world` (`0x00405960`) from timeline |
| `run_active` (`0x00487240`) | render gating | dispatcher uses it to choose terrain-only vs full pass |
| `game_paused_flag` (`0x004808b8`) | pause toggle | checked in the main frame loop |
| `demo_mode_active` (`0x0048700d`) | demo/attract gating | disables HUD and alters update behavior |

## Transition rules

- `ui_elements_update_and_render` updates `ui_elements_timeline` (`0x00487248`). When it drops below `0`,
  it calls `game_state_set` (`0x004461c0`) with `game_state_pending` (`0x00487274`) and then sets `game_state_pending` (`0x00487274`) = `0x19`.

- Menu buttons set `game_state_pending` (`0x00487274`) = `9` (Survival/Rush) or `game_state_pending` (`0x00487274`) = `0x12`
  (Typ-o-Shooter), then clear `ui_transition_direction` (`0x0048724c`) to start the transition.

- Quest completion sets `game_state_pending` (`0x00487274`) = `8` after the final spawn wave.
- Player death sets `game_state_pending` (`0x00487274`) = `7` for non-quest modes or `0xc` for quests.
- Perk selection uses a direct `game_state_set` (`0x004461c0(6)`) instead of a queued transition.
- `game_pause` (console/mod command) sets `game_state_pending` (`0x00487274`) = `5`.
