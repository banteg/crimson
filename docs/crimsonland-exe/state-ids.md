---
tags:
  - status-analysis
---

# State id glossary
This page maps numeric `game_state_id` values in `crimsonland.exe` (v1.9.93).

Primary static anchors:

- `game_state_set` (`FUN_004461c0`, `0x004461c0`)
- Main frame dispatch in `grim_update` (`0x0040c840` region)
- `ui_elements_update_and_render` (`FUN_0041a530`, `0x0041a530`)

Runtime cross-check:

- `analysis/frida/ui_render_trace_oracle_1024x768.json` labels (`state_<id>:...`)

## State values

| Dec | Hex | Meaning (inferred) | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| `0` | `0x00` | Main menu | `game_state_set(0)` seeds root menu UI; runtime label `state_0`. | high |
| `1` | `0x01` | Play Game menu | Main-menu callback sets `game_state_pending = 1`; runtime label `state_1:Quests`. | high |
| `2` | `0x02` | Options menu | Main-menu callback sets `game_state_pending = 2`; runtime label `state_2:Sound volume:`. | high |
| `3` | `0x03` | Controls/config menu | Main-menu callback sets `game_state_pending = 3`; runtime label `state_3:Configure for:`. | high |
| `4` | `0x04` | Statistics hub | `game_state_set(4)` seeds stats UI; credits/back flow returns to `4`; runtime label `state_4:played for # hours # minutes`. | high |
| `5` | `0x05` | Pause/menu overlay | `mod_api_cl_enter_menu(\"game_pause\")` sets `game_state_pending = 5`; runtime label `state_5`. | high |
| `6` | `0x06` | Perk selection | Direct `game_state_set(6)` from perk prompt; dispatch calls `perk_selection_screen_update`; runtime label `state_6`. | high |
| `7` | `0x07` | Game-over screen | Dispatch calls `game_over_screen_update`; non-quest death queues `7`. | high |
| `8` | `0x08` | Quest results screen | Dispatch calls `quest_results_screen_update`; quest completion queues `8`; runtime label `state_8`. | high |
| `9` | `0x09` | Main gameplay loop (Survival/Rush/Quest) | Dispatch calls `gameplay_update_and_render`; runtime label `state_9`. | high |
| `10` | `0x0a` | Quit transition state | Main-menu Quit sets `game_state_pending = 10`; `ui_elements_update_and_render` checks `game_state_id == 10` and sets quit latch (`DAT_0047ea50`). | high |
| `11` | `0x0b` | Quest select menu | Quest-failed flow queues `0x0b`; `game_state_set(0x0b)` enables quest menu UI; runtime label `state_11:#.#`. | high |
| `12` | `0x0c` | Quest-failed screen | Dispatch calls `quest_failed_screen_update`; quest death queues `0x0c`. | high |
| `13` | `0x0d` | High-score setup variant (legacy/unclear) | `game_state_set(0x0d)` calls `highscore_load_table()` and installs no-op callback `ui_callback_noop`; no direct `game_state_pending = 0x0d` write seen in this build. | medium |
| `14` | `0x0e` | High scores screen | `game_state_set(0x0e)` installs callback `sub_4423d0`; game-over/quest-results High scores buttons queue `0x0e`; runtime labels `state_14:High scores - ...`. | high |
| `15` | `0x0f` | Unlocked Weapons Database | `game_state_set(0x0f)` installs callback `sub_440110`; runtime label `state_15:Unlocked Weapons Database`. | high |
| `16` | `0x10` | Unlocked Perks Database | `game_state_set(0x10)` installs callback `sub_440960`; runtime label `state_16:Unlocked Perks Database`. | high |
| `17` | `0x11` | Credits | `game_state_set(0x11)` installs `credits_screen_update`; runtime label `state_17:credits`. | high |
| `18` | `0x12` | Typ-o-Shooter gameplay | Dispatch calls `typo_gameplay_update_and_render`; Play Again in Typ-o paths queues `0x12`. | high |
| `19` | `0x13` | Unknown menu-state variant (unused in observed flow) | `game_state_set(0x13)` toggles generic menu block flags but installs no unique update callback; no direct transition writes found. | low |
| `20` | `0x14` | Mods browser/menu (also plugin fallback) | `game_state_set(0x14)` installs callback `sub_40e9a0` (mods list/launch UI); plugin flow queues `0x14` when plugin is missing/exits. | high |
| `21` | `0x15` | Final-quest end note / victory screen | Dispatch calls `game_update_victory_screen`; final quest results queue `0x15`. | high |
| `22` | `0x16` | Active plugin/mod runtime screen | Dispatch routes to plugin flow `plugin_runtime_update_and_render`; mods menu Launch queues `0x16`. | high |
| `23` | `0x17` | Unknown / unused | No `game_state_set(0x17)` case and no dispatch branch observed. | low |
| `24` | `0x18` | Legacy demo/gameplay+upsell branch | Dispatch has special `game_state_id == 0x18` path (`gameplay_update_and_render` + `demo_purchase_screen_update`); no direct transition write to `0x18` found in this build. | medium |
| `25` | `0x19` | Pending-state idle sentinel (not a real state) | After transition commit, `ui_elements_update_and_render` sets `game_state_pending = 0x19`. | high |
| `26` | `0x1a` | Credits secret screen (Alien ZooKeeper) | Credits secret button queues `0x1a`; `game_state_set(0x1a)` installs `credits_secret_alien_zookeeper_update`. | high |

## Notes

- Runtime trace labels use decimal (`state_14`, `state_17`, etc.), while decompile references are often hex (`0x0e`, `0x11`).
- State `0x19` is only a sentinel for `game_state_pending` and should not be treated as a normal `game_state_id`.
- States marked low/medium confidence need either a direct transition capture (Frida/WinDbg) or additional static xref evidence.
