# Rewrite status (Python + raylib)

This page tracks the current code-level state of the rewrite under `src/`, and the
largest remaining parity gaps vs the classic Windows build (v1.9.93) documented in
[`docs/crimsonland-exe/`](../crimsonland-exe/).

## What you can run today

- `uv run crimson`
  - Full boot flow (splash + company logos) -> main menu.
  - Play Game / Options / Statistics / Mods menu flows.
  - Survival / Rush / Quests / Typ-o-Shooter / Tutorial are all wired and playable.
  - Game over -> high score entry (Survival/Rush/Typ-o), and quest completion/failure flows.
- `uv run crimson --preserve-bugs` to re-enable known native quirks for parity/diff work.
- `uv run crimson view <name>` for debug views and sandboxes.
- `uv run crimson spawn-plan <template_id>` and `uv run crimson quests <level>` for spawn/script inspection.
- Local co-op and replays are supported; [network play is deferred](netplay.md).
- Asset tooling:
  - `cd crimson-zig && zig build --prefix zig-out && ./zig-out/bin/crimson-zig-asset-smoke <assets-dir>`
    - The installed native smoke tool validates `crimson.paq`, JAZ/TGA/JPEG image decoding, runtime texture specs, and small-font width data.
  - `cd crimson-zig && zig build --prefix zig-out && ./zig-out/bin/crimson-zig-asset-extract <game-dir> <assets-dir>`
    - The installed native extractor walks `.paq` files, preserves the Python extractor's `<assets-dir>/<paq-stem>/...` layout, writes raw payloads, and converts decoded JAZ/TGA entries to PNG.
- Desktop shell:
  - `cd crimson-zig && zig build --prefix zig-out && ./zig-out/bin/crimson-zig-window`
    - The installed native desktop shell starts the boot/menu/gameplay product flow; `--demo` starts with shareware demo limits enabled.
- Replay tooling:
  - `uv run crimson replay play <replay.crd>`
  - `uv run crimson replay verify <replay.crd>`
  - `uv run crimson replay info <replay.crd>` (core timeline by default; `--verbose` adds extra context events; `--format json` emits schema-versioned timeline payload)
  - `uv run crimson replay benchmark <replay.crd>` (default `--mode headless`, optional `--mode render`)
  - `uv run crimson replay render <replay.crd>` (ffmpeg-backed 60fps MP4 export, quality via `--crf/--preset`)
  - `uv run crimson replay verify-checkpoints <replay.crd>`
  - `uv run crimson replay diff-checkpoints <expected> <actual>`
- Original/capture differential tooling (via structural traces):
  - `uv run --with frida==17.15.4 python scripts/frida/gameplay_diff_capture_host.py --raw-path <capture.jsonl> --output-dir <dir>` (add `--finalize-only` to finalize without attaching)
  - `uv run crimson dbg record <replay.crd> --impl python --out <trace.py.cdt>`
  - `uv run crimson dbg record <replay.crd> --impl zig --out <trace.zig.cdt>`
  - `crimson-zig dbg record <replay.crd> --out <trace.zig.cdt>`
  - `crimson-zig dbg health <trace.cdt> --format json`
  - `crimson-zig dbg tick <trace.cdt> <tick> --json`
  - `crimson-zig dbg entity <trace.cdt> <entity_uid> --json`
  - `crimson-zig dbg query <trace.cdt> "entities where uid == 0" --json`
  - `crimson-zig dbg verify`
  - `crimson-zig config --path <crimson.cfg> --format json`
  - `crimson-zig status --path <game.cfg> --format json`
  - `crimson-zig quests <level> --format json --seed <seed>`
  - `crimson-zig quests <level> --show-plan`
  - `crimson-zig spawn-plan <template_id> --json` (add `--no-demo-mode-active` to include runtime burst effects)
  - `uv run crimson dbg health <trace.cdt>`
  - `uv run crimson dbg tick <trace.cdt> <tick>`
  - `uv run crimson dbg entity <trace.cdt> <entity_uid>`
  - `uv run crimson dbg query <trace.cdt> "entities where uid == 0"`
  - `uv run crimson dbg diff <expected.cdt> <actual.cdt>`
  - `uv run crimson dbg bisect <expected.cdt> <actual.cdt>`
  - `uv run crimson dbg focus <expected.cdt> <actual.cdt> --tick <n>`

## Zig native port status

- Zig native-port details now live on a dedicated page:
  - [`docs/rewrite/zig-verifier.md`](zig-verifier.md)
- `crimson-zig/` is being tracked as a full native port effort, not a verifier
  side project.
- This page remains focused on overall rewrite (Python + raylib) status and
  major parity gaps, while the Zig page tracks the native-port surface directly.

## Coverage map (rewrite vs classic)

### Front-end (menus + screens)

- **Main menu (state `0`)**: implemented, including timeline/layout behavior and terrain/sign-shadow rules.
  - Code: `src/crimson/screens/menu.py`
  - Ref: [`docs/crimsonland-exe/main-menu.md`](../crimsonland-exe/main-menu.md)
  - Zig now routes root menu selections and demo-idle attract launch through the native close timeline before dispatch.
- **Play Game panel (state `1`)**: implemented (mode buttons, player-count dropdown, tooltips, debug-gated F1 times-played overlay).
  - Code: `src/crimson/game/__init__.py` (`PlayGameMenuView`)
  - Ref: [`docs/crimsonland-exe/play-game-menu.md`](../crimsonland-exe/play-game-menu.md)
- **Quest select menu (state `0x0b`)**: implemented (quest list, stage icons, hardcore gating, debug-gated counts overlay and F5 unlock shortcut).
  - Code: `src/crimson/game/__init__.py` (`QuestsMenuView`)
  - Ref: [`docs/crimsonland-exe/quest-select-menu.md`](../crimsonland-exe/quest-select-menu.md)
- **Options panel (state `2`)**: implemented for core sliders + controls workflow.
  - Code: `src/crimson/screens/panels/options.py`, `src/crimson/screens/panels/controls.py`, `crimson-zig/src/window_options.zig`
  - Implemented: SFX/music/detail/mouse sliders, UI info toggle, display config editing, controls entry and interactive rebinding flow. Zig now routes Options/Controls navigation through the native 300 ms panel close timeline before dispatching Back or Controls actions.
- **Statistics hub (state `4`)**: implemented with child panels.
  - Code: `src/crimson/screens/panels/stats.py`
  - Child views: high scores, weapons database, perks database, credits.
  - Code: `src/crimson/game/__init__.py`, `src/crimson/screens/panels/databases.py`, `src/crimson/screens/panels/credits.py`, `crimson-zig/src/window_statistics.zig`
  - Zig now gates the hub buttons until the native 300 ms open timeline completes and closes both the hub and child panels before dispatching descendant or Back actions.
- **Demo / attract mode**: implemented (variant sequencing, upsell flow, trial overlay during gameplay).
  - Code: `src/crimson/demo.py`, `src/crimson/ui/demo_trial_overlay.py`
  - Ref: [`docs/crimsonland-exe/demo-mode.md`](../crimsonland-exe/demo-mode.md), [`docs/crimsonland-exe/screens.md`](../crimsonland-exe/screens.md)
- **Game over / high score entry (state `7`)**: implemented for Survival/Rush/Typ-o.
  - Code: `src/crimson/ui/game_over.py`, `src/crimson/persistence/highscores.py`, `src/crimson/game/__init__.py`
  - Zig now animates game-over/results panels through the native open/close slide timeline, keeps high-score/button hitboxes aligned with the moving panel, routes Play Again, High scores, and Main Menu actions through the native close timeline before dispatch, returns Back from result-launched high scores to the results screen, and clears that stacked results screen before Play a game opens Play Game.
- **Quest results (state `8`) / quest failed (state `0x0c`)**: implemented.
  - Code: `src/crimson/ui/quest_results.py`, `src/crimson/game/__init__.py`, `crimson-zig/src/window_main.zig`
  - Zig quest-completion results show the resolved weapon/perk unlock names after the final-time breakdown completes, honor the completed-results keyboard shortcuts, and route the final quest end-note screen through the native 300 ms open/close timeline before dispatching its follow-up action.
- **Pause menu**: implemented.
  - Code: `src/crimson/screens/pause_menu.py`, `crimson-zig/src/window_pause_menu.zig`
  - Zig now routes pause-menu Back, Options, and Quit actions through the native close timeline before dispatch.
- **Mods menu (state `0x14` path from main menu)**: implemented as a panel and filesystem DLL discovery UI; plugin loading/runtime is still not implemented.
  - Code: `src/crimson/screens/panels/mods.py`, `src/crimson/screens/menu.py`
  - Ref: [`docs/crimsonland-exe/mods.md`](../crimsonland-exe/mods.md)
  - Zig now routes Mods and Other Games panel Back actions through the native panel timeline before dispatch.
- **Scope policy for Mods and Other Games/shareware ads**: out of scope for the rewrite target.
  - Rationale: native DLL plugin runtime is not practical to support in the Python rewrite architecture.
  - Rewrite stance: keep menu-shell UX compatibility where useful, but do not implement native DLL mod loading/execution or Other Games ad/runtime flows.
- **Secrets / extras**: implemented, including the Alien Zoo Keeper credits secret flow.
  - Code: `src/crimson/screens/panels/alien_zookeeper.py`, `src/crimson/screens/panels/credits.py`

### Gameplay

- **Core world sim**: `GameWorld` is the active runtime container (players, creatures, projectiles, bonuses/perks, FX, terrain renderer).
  - Code: `src/crimson/game_world.py`
- **Playable modes**: Survival, Rush, Quests, Typ-o-Shooter, Tutorial are all wired through the shared gameplay framework.
  - Code: `src/crimson/modes/*.py`
- **Quest content**: tiers 1-5 are present and script-driven through runtime builders.
  - Code: `src/crimson/quests/tier*.py`, `src/crimson/quests/runtime.py`
- **Multiplayer**: local 2-4 player input-frame flow is implemented for Survival/Rush/Quest.
  - Code: `src/crimson/modes/base_gameplay_mode.py`, `src/crimson/local_input.py`
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
- Deterministic step pipeline parity (live update vs replay/headless execution) is covered with canonical tick and checkpoint/state parity tests.
  - Tests: `tests/test_step_pipeline_parity.py`, `tests/test_replay_runners_survival.py`, `tests/test_replay_runners_rush.py`, `tests/test_replay_runners_quest.py`
  - Code: `src/crimson/sim/sessions.py`, `src/crimson/sim/tick_runner.py`, `src/crimson/sim/driver/playback_driver.py`
- Replay-side checkpoint differential comparison is reusable via CLI and library helpers.
  - Code: `src/crimson/dbg/checkpoint_diff.py`
  - Command: `uv run crimson replay diff-checkpoints <expected> <actual>`
- Replay timeline extraction now has a versioned JSON surface for analytics/web infographics.
  - Code: `src/crimson/sim/driver/replay_info.py`, `src/crimson/cli/replay.py`
  - Command: `uv run crimson replay info <replay.crd> --format json --json-out <path>`
- Capture import and trace diagnostics are managed via the decoupled `dbg` trace suite.
  - Code: `src/crimson/dbg/*`
  - Documentation: [`docs/frida/differential-playbook.md`](../frida/differential-playbook.md)
  - Tooling includes health, structural diffs across implementations, bisection, and focus trace.
- Capture-only triage workflow is documented here:
  - [`docs/frida/differential-playbook.md`](../frida/differential-playbook.md)

## 4-player extension policy

- Exact parity target: native `1/2` player behavior.
- Deterministic extension target: `3/4` players follow the same per-player rules without perturbing `1/2` outcomes.
- Current examples:
  - Survival/Rush high-score ownership remains player-0-centric.
  - Quest final-time life bonus aggregates all players for `3/4` runs while preserving native `1/2` behavior.

## Biggest remaining parity gaps (vs v1.9.93)

1. **Ongoing deep parity validation**
   - Deterministic parity infrastructure is in place; remaining gaps are mostly capture-backed edge-case timing and branch-order issues.
   - This status page intentionally avoids tick/session-specific examples that go stale quickly.
   - Current active probes and per-SHA outcomes are tracked in [`docs/frida/differential-sessions.md`](../frida/differential-sessions.md).

## Out of scope for this rewrite

1. **Native DLL mods/plugin runtime**
   - We do not plan to support loading/executing original DLL mods from Python.
2. **Other Games/shareware ad flows**
   - Shareware ad/runtime paths are not part of the parity target.
3. **Native online-score submission**
   - Local high-score tables stay supported, but we do not target original online score submission.
   - Direction: use a more advanced headless verification system for score legitimacy/parity evidence.
