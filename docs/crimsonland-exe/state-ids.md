---
tags:
  - status-analysis
---

# State id glossary
This page maps numeric `game_state_id` values in `crimsonland.exe` (v1.9.93).
The names come from `game_state_id_t` in `third_party/headers/crimsonland_types.h`.

Source anchors:

- `game_state_set` (`0x004461c0`, `decomp/1.9/crimsonland/ui_elements/game_state_set.cpp`)
- Per-frame state dispatch in `game_frame_update` (`0x0040c1c0`, `decomp/1.9/crimsonland/game/game_frame_update.cpp`)
- `ui_elements_update_and_render` (`0x0041a530`, `decomp/1.9/crimsonland/ui_render/ui_elements_update_and_render.cpp`)

## State values

| Dec | Hex | `game_state_id_t` | Meaning | Evidence |
| --- | --- | --- | --- | --- |
| `0` | `0x00` | `GAME_STATE_MAIN_MENU` | Main menu | `game_core_init` calls `game_state_set(0)`, which seeds the root menu UI. |
| `1` | `0x01` | `GAME_STATE_PLAY_GAME_MENU` | Play Game menu | Main-menu callback sets `game_state_pending = 1`; state callback is `play_game_menu_update`. |
| `2` | `0x02` | `GAME_STATE_OPTIONS_MENU` | Options menu | Main-menu callback sets `game_state_pending = 2`; state callback is `options_menu_update`. |
| `3` | `0x03` | `GAME_STATE_CONTROLS_MENU` | Controls/config menu | Main-menu callback sets `game_state_pending = 3`; state callback is `controls_menu_update`. |
| `4` | `0x04` | `GAME_STATE_STATISTICS_MENU` | Statistics hub | `game_state_set(4)` installs `statistics_menu_update`; credits, databases and high scores return to `4`. |
| `5` | `0x05` | `GAME_STATE_PAUSE_MENU` | Pause/menu overlay | Escape in gameplay, the contextual Back button and `mod_api_cl_enter_menu("game_pause")` set `game_state_pending = 5`. |
| `6` | `0x06` | `GAME_STATE_PERK_SELECTION` | Perk selection | Direct `game_state_set(6)` from the perk prompt in `gameplay_update_and_render`; dispatch calls `perk_selection_screen_update`. |
| `7` | `0x07` | `GAME_STATE_GAME_OVER` | Game-over screen | Dispatch calls `game_over_screen_update`; non-quest death queues `7`. |
| `8` | `0x08` | `GAME_STATE_QUEST_RESULTS` | Quest results screen | Dispatch calls `quest_results_screen_update`; `quest_mode_update` queues `8`. |
| `9` | `0x09` | `GAME_STATE_GAMEPLAY` | Main gameplay loop (Survival/Rush/Quest) | Dispatch calls `gameplay_update_and_render` (and `demo_purchase_screen_update` in demo mode). |
| `10` | `0x0a` | `GAME_STATE_QUIT_TRANSITION` | Quit transition state | Main-menu Quit sets `game_state_pending = 10`; `ui_elements_update_and_render` sets `quit_requested` while `game_state_id == 10`. |
| `11` | `0x0b` | `GAME_STATE_QUEST_SELECT` | Quest select menu | Play Game and quest-failed flows queue `0x0b`; `game_state_set(0x0b)` installs `quest_select_menu_update`. |
| `12` | `0x0c` | `GAME_STATE_QUEST_FAILED` | Quest-failed screen | Dispatch calls `quest_failed_screen_update`; quest death queues `0x0c`. |
| `13` | `0x0d` | `GAME_STATE_HIGHSCORE_LEGACY` | Legacy high-score setup (unreachable) | `game_state_set(0x0d)` loads the high-score table and installs `ui_callback_noop`; nothing queues or sets `0x0d`. |
| `14` | `0x0e` | `GAME_STATE_HIGHSCORES` | High scores screen | `game_state_set(0x0e)` installs `highscore_screen_update`; game-over, quest-results and statistics High scores buttons queue `0x0e`. |
| `15` | `0x0f` | `GAME_STATE_WEAPON_DATABASE` | Unlocked Weapons Database | `game_state_set(0x0f)` installs `unlocked_weapons_database_update`. |
| `16` | `0x10` | `GAME_STATE_PERK_DATABASE` | Unlocked Perks Database | `game_state_set(0x10)` installs `unlocked_perks_database_update`. |
| `17` | `0x11` | `GAME_STATE_CREDITS` | Credits | `game_state_set(0x11)` installs `credits_screen_update`. |
| `18` | `0x12` | `GAME_STATE_TYPO_GAMEPLAY` | Typ-o-Shooter gameplay | Dispatch calls `typo_gameplay_update_and_render`; Play Game, Play Again and resume paths queue `0x12`. |
| `19` | `0x13` | `GAME_STATE_MENU_LEGACY_VARIANT` | Legacy menu variant (unreachable) | `game_state_set(0x13)` activates the sign and slot 9 but installs no update callback; nothing queues or sets `0x13`. |
| `20` | `0x14` | `GAME_STATE_MODS_MENU` | Mods browser/menu (also plugin fallback) | `game_state_set(0x14)` installs `mods_menu_update`; the plugin flow queues `0x14` when the plugin is missing or exits. |
| `21` | `0x15` | `GAME_STATE_FINAL_QUEST_END_NOTE` | Final-quest end note / victory screen | Dispatch calls `game_update_victory_screen`; final quest results queue `0x15`. |
| `22` | `0x16` | `GAME_STATE_PLUGIN_RUNTIME` | Active plugin/mod runtime screen | Dispatch routes to `plugin_runtime_update_and_render`; mods menu Launch and pause Resume (while a plugin is active) queue `0x16`. |
| `23` | `0x17` | `GAME_STATE_UNUSED_0X17` | Unused | No `game_state_set` case, no dispatch branch, no writer. |
| `24` | `0x18` | `GAME_STATE_DEMO_UPSELL_GAMEPLAY` | Demo gameplay + upsell (unreachable) | Dispatch has a branch (`gameplay_update_and_render` + `demo_purchase_screen_update`) and the transition fade checks `game_state_prev == 0x18`, but nothing queues or sets `0x18`. |
| `25` | `0x19` | `GAME_STATE_PENDING_IDLE_SENTINEL` | Pending-state idle sentinel (not a real state) | After committing a transition, `ui_elements_update_and_render` sets `game_state_pending = 0x19`. |
| `26` | `0x1a` | `GAME_STATE_CREDITS_SECRET` | Credits secret screen (Alien ZooKeeper) | Credits Secret button queues `0x1a`; `game_state_set(0x1a)` installs `credits_secret_alien_zookeeper_update`. |

## Notes

- States only change through `game_state_set`, called either directly
  (`game_core_init` with `0`, the perk prompt with `6`, `demo_mode_start` with
  `9`) or from `ui_elements_update_and_render` with `game_state_pending`. Every
  `game_state_pending` write in the recovered source uses a literal (or a
  ternary of literals) from the reachable set, so `0x0d`, `0x13`, `0x17` and
  `0x18` are never entered in 1.9.93.
- State `0x19` is only a sentinel for `game_state_pending` and should not be treated as a normal `game_state_id`.

## Historical runtime capture (2026-02-06)

Before the decompilation was complete, a Frida capture
(`analysis/frida/gameplay_state_capture_summary.json`, ~694 s) recorded the
`game_state_set` targets `0,1,2,3,4,5,6,7,8,9,10,11,12,14,15,16,17,26`, with the
most frequent transitions `1 -> 9`, `9 -> 6 -> 9`, `9 -> 8 -> 9` and
`7 -> 14 -> 7`. The UI render oracle
(`analysis/frida/ui_render_trace_oracle_1024x768.json`) labels frames with
decimal ids (`state_14:High scores - ...`). Both are consistent with the
recovered source above.
