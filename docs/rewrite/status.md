# Rewrite status (Python + raylib)

This page tracks the current code-level state of the rewrite under `src/`, and the
largest remaining parity gaps vs the classic Windows build (v1.9.93) documented in
[`docs/crimsonland-exe/`](../crimsonland-exe/).

Last reviewed: **2026-02-13**

## What you can run today

- `uv run crimson`
  - Full boot flow (splash + company logos) -> main menu.
  - Play Game / Options / Statistics / Mods menu flows.
  - Survival / Rush / Quests / Typ-o-Shooter / Tutorial are all wired and playable.
  - Game over -> high score entry (Survival/Rush/Typ-o), and quest completion/failure flows.
- `uv run crimson --preserve-bugs` to re-enable known native quirks for parity/diff work.
- `uv run crimson view <name>` for debug views and sandboxes.
- `uv run crimson spawn-plan <template_id>` and `uv run crimson quests <level>` for spawn/script inspection.
- LAN bring-up tooling:
  - `uv run crimson lan host --mode survival --players 2`
  - `uv run crimson lan join --host <ip> --port 31993`
- Replay tooling:
  - `uv run crimson replay play <replay.crdemo.gz>`
  - `uv run crimson replay verify <replay.crdemo.gz>`
  - `uv run crimson replay diff-checkpoints <expected> <actual>`
- Original/capture differential tooling:
  - `uv run crimson original verify-capture <capture.json>`
  - `uv run crimson original convert-capture <capture.json> <expected.checkpoints.json.gz>`
  - `uv run crimson original divergence-report <capture.json>`
  - `uv run crimson original bisect-divergence <capture.json>`
  - `uv run crimson original focus-trace <capture.json> --tick <n>`
  - `uv run crimson original creature-trajectory <capture.json>`
  - `uv run crimson original visualize-capture <capture.json>`

## Coverage map (rewrite vs classic)

### Front-end (menus + screens)

- **Main menu (state `0`)**: implemented, including timeline/layout behavior and terrain/sign-shadow rules.
  - Code: `src/crimson/frontend/menu.py`
  - Ref: [`docs/crimsonland-exe/main-menu.md`](../crimsonland-exe/main-menu.md)
- **Play Game panel (state `1`)**: implemented (mode buttons, player-count dropdown, tooltips, F1 times-played overlay).
  - Code: `src/crimson/game/__init__.py` (`PlayGameMenuView`)
  - Ref: [`docs/crimsonland-exe/play-game-menu.md`](../crimsonland-exe/play-game-menu.md)
- **Quest select menu (state `0x0b`)**: implemented (quest list, stage icons, hardcore gating/counts overlay).
  - Code: `src/crimson/game/__init__.py` (`QuestsMenuView`)
  - Ref: [`docs/crimsonland-exe/quest-select-menu.md`](../crimsonland-exe/quest-select-menu.md)
- **Options panel (state `2`)**: implemented for core sliders + controls workflow.
  - Code: `src/crimson/frontend/panels/options.py`, `src/crimson/frontend/panels/controls.py`
  - Implemented: SFX/music/detail/mouse sliders, UI info toggle, controls entry and interactive rebinding flow.
  - Not exposed in this in-game UI: `screen_width`, `screen_height`, `windowed_flag`, `screen_bpp`, `texture_scale` editing (currently config/CLI-managed).
- **Statistics hub (state `4`)**: implemented with child panels.
  - Code: `src/crimson/frontend/panels/stats.py`
  - Child views: high scores, weapons database, perks database, credits.
  - Code: `src/crimson/game/__init__.py`, `src/crimson/frontend/panels/databases.py`, `src/crimson/frontend/panels/credits.py`
- **Demo / attract mode**: implemented (variant sequencing, upsell flow, trial overlay during gameplay).
  - Code: `src/crimson/demo.py`, `src/crimson/ui/demo_trial_overlay.py`
  - Ref: [`docs/crimsonland-exe/demo-mode.md`](../crimsonland-exe/demo-mode.md), [`docs/crimsonland-exe/screens.md`](../crimsonland-exe/screens.md)
- **Game over / high score entry (state `7`)**: implemented for Survival/Rush/Typ-o.
  - Code: `src/crimson/ui/game_over.py`, `src/crimson/persistence/highscores.py`, `src/crimson/game/__init__.py`
- **Quest results (state `8`) / quest failed (state `0x0c`)**: implemented.
  - Code: `src/crimson/ui/quest_results.py`, `src/crimson/game/__init__.py`
- **Mods menu (state `0x14` path from main menu)**: implemented as a panel and filesystem DLL discovery UI; plugin loading/runtime is still not implemented.
  - Code: `src/crimson/frontend/panels/mods.py`, `src/crimson/frontend/menu.py`
  - Ref: [`docs/crimsonland-exe/mods.md`](../crimsonland-exe/mods.md)
- **Scope policy for Mods and Other Games/shareware ads**: out of scope for the rewrite target.
  - Rationale: native DLL plugin runtime is not practical to support in the Python rewrite architecture.
  - Rewrite stance: keep menu-shell UX compatibility where useful, but do not implement native DLL mod loading/execution or Other Games ad/runtime flows.
- **Secrets / extras**: implemented, including the Alien Zoo Keeper credits secret flow.
  - Code: `src/crimson/frontend/panels/alien_zookeeper.py`, `src/crimson/frontend/panels/credits.py`

### Gameplay

- **Core world sim**: `GameWorld` is the active runtime container (players, creatures, projectiles, bonuses/perks, FX, terrain renderer).
  - Code: `src/crimson/game_world.py`
- **Playable modes**: Survival, Rush, Quests, Typ-o-Shooter, Tutorial are all wired through the shared gameplay framework.
  - Code: `src/crimson/modes/*.py`
- **Quest content**: tiers 1-5 are present and script-driven through runtime builders.
  - Code: `src/crimson/quests/tier*.py`, `src/crimson/quests/runtime.py`
- **Multiplayer**: local 2-4 player input-frame flow is implemented for Survival/Rush/Quest.
  - Code: `src/crimson/modes/base_gameplay_mode.py`, `src/crimson/local_input.py`
- **LAN lockstep foundation**: protocol/lobby/reliability/lockstep/resync core is implemented, with CLI and feature-gated UI session setup.
  - Code: `src/crimson/net/*.py`, `src/crimson/cli.py`, `src/crimson/frontend/panels/lan_session.py`, `src/crimson/game/loop_view.py`
  - Doc: [`docs/rewrite/lan-lockstep.md`](lan-lockstep.md)
- **Progression/unlocks/persistence**: quest unlock indices, mode play counters, and status persistence are wired.
  - Code: `src/crimson/persistence/save_status.py`, `src/crimson/gameplay.py`
- **Content breadth**: rewrite tables and runtime paths cover full weapon/perk/quest content, with ongoing parity validation focused on edge-case behavior/timing through differential captures.

### Audio

- **Audio routing** (`AudioRouter`) is implemented and wired for gameplay events.
  - Code: `src/crimson/audio_router.py`
  - Includes per-creature death SFX routing, hit/explosion variants, weapon fire/reload mapping, and gameplay music triggers.

## Verification and parity evidence

- Ground renderer parity is fixture-tested against runtime dumps.
  - Doc: [`docs/rewrite/terrain.md`](terrain.md)
  - Test: `tests/test_ground_dump_fixtures.py`
- Deterministic step pipeline parity (live update vs replay/headless runners) is covered with command-hash checks.
  - Tests: `tests/test_step_pipeline_parity.py`, `tests/test_replay_runners.py`
  - Code: `src/crimson/sim/sessions.py`, `src/crimson/sim/runners/*.py`
- LAN lockstep protocol/state-machine behavior is covered by unit and wiring tests.
  - Tests: `tests/test_lan_protocol.py`, `tests/test_lan_reliable_channel.py`, `tests/test_lan_lobby_handshake.py`, `tests/test_lan_lockstep_host.py`, `tests/test_lan_lockstep_client.py`, `tests/test_lan_desync_resync.py`, `tests/test_lan_cli.py`, `tests/test_lan_ui_flow.py`
- Replay-side checkpoint differential comparison is reusable via CLI and library helpers.
  - Code: `src/crimson/original/diff.py`
  - Command: `uv run crimson replay diff-checkpoints <expected> <actual>`
- Original-capture conversion and capture-native verification are implemented.
  - Code: `src/crimson/original/capture.py`, `src/crimson/original/verify.py`
  - Tests: `tests/test_original_capture_conversion.py`, `tests/test_original_capture_verify.py`
- Divergence triage tooling (report, bisect, focus trace, visualizer) is in-tree and wired through `crimson original`.
  - Code: `src/crimson/original/divergence_report.py`, `src/crimson/original/divergence_bisect.py`, `src/crimson/original/focus_trace.py`, `src/crimson/original/capture_visualizer.py`
- Capture-only triage workflow is documented here:
  - [`docs/frida/differential-playbook.md`](../frida/differential-playbook.md)

## 4-player extension policy

- Exact parity target: native `1/2` player behavior.
- Deterministic extension target: `3/4` players follow the same per-player rules without perturbing `1/2` outcomes.
- Current examples:
  - Survival/Rush high-score ownership remains player-0-centric.
  - Quest final-time life bonus aggregates all players for `3/4` runs while preserving native `1/2` behavior.

## Biggest remaining parity gaps (vs v1.9.93)

1. **Options parity completeness**
   - In-game options do not currently edit display/config fields:
     - `screen_width`
     - `screen_height`
     - `windowed_flag`
     - `screen_bpp`
     - `texture_scale`
   - These fields are persisted/used, but today are managed via `crimson.cfg` + CLI/runtime startup, not the state-2 panel.
2. **Ongoing deep parity validation**
   - Deterministic parity infrastructure is in place; remaining gaps are mostly capture-backed edge-case timing and branch-order issues.
   - This status page intentionally avoids tick/session-specific examples that go stale quickly.
   - Current active probes and per-SHA outcomes are tracked in [`docs/frida/differential-sessions.md`](../frida/differential-sessions.md).
3. **LAN lockstep end-to-end match wiring**
   - `src/crimson/net/*` transport/lobby/lockstep/resync modules are in-tree, but live packet pump integration into gameplay mode update loops is still staged.
   - Current UI/CLI surfaces are intended for bring-up and wiring validation while phased rollout proceeds.

## Out of scope for this rewrite

1. **Native DLL mods/plugin runtime**
   - We do not plan to support loading/executing original DLL mods from Python.
2. **Other Games/shareware ad flows**
   - Shareware ad/runtime paths are not part of the parity target.
3. **Native online-score submission**
   - Local high-score tables stay supported, but we do not target original online score submission.
   - Direction: use a more advanced headless verification system for score legitimacy/parity evidence.
