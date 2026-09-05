---
tags:
  - rewrite
  - architecture
---

# Module map

The Python port has two packages. `grim` provides platform, resource and rendering
services; `crimson` owns the game. The split is not a strict one-way import
boundary: `grim.config` uses game enums/quest identifiers, and `grim.terrain_render`
uses native RNG caller tags. It reflects the original engine/game separation
without requiring the port to reproduce its global layout or virtual interface.

| Responsibility | Implementation |
| --- | --- |
| Window, loop, debug view protocol | `src/grim/app.py`, `src/grim/view.py` |
| Archive/image decoding and asset access | `src/grim/paq.py`, `src/grim/jaz.py`, `src/grim/assets.py` |
| Input, audio, fonts, configuration | `src/grim/input.py`, `src/grim/audio.py`, `src/grim/fonts/`, `src/grim/config.py` |
| CLI and tools | `src/crimson/cli/` |
| Navigation and application resources | `src/crimson/game/navigation.py`, `src/crimson/game/resources.py` |
| Screens, typed actions and retained stack | `src/crimson/screens/`, `src/crimson/screens/actions.py`, `src/crimson/screens/stack.py` |
| Gameplay shell and mode-specific UI | `src/crimson/modes/` |
| Run inputs and initialization | `src/crimson/sim/run_spec.py`, `src/crimson/sim/run_init.py` |
| Deterministic session and world state | `src/crimson/sim/sessions.py`, `src/crimson/sim/world_state.py` |
| Replay codec, recording and driving | `src/crimson/replay/` |
| Camera, terrain and audio application | `src/crimson/world/` |
| World drawing and atlas coordinates | `src/crimson/render/world/`, `src/crimson/atlas.py` |
| Creature, projectile, perk and bonus behavior | `src/crimson/creatures/`, `src/crimson/projectiles/`, `src/crimson/perks/`, `src/crimson/bonuses/` |
| Quest content, tutorial and typing rules | `src/crimson/quests/`, `src/crimson/tutorial/`, `src/crimson/typo/` |
| Saves and high scores | `src/crimson/persistence/` |
| Trace recording, comparison and state inspection | `src/crimson/dbg/` |

## Ownership

`ScreenNavigator` coordinates typed screen requests through `ScreenStack`. Back
resumes a retained screen; it does not reopen its run. Modes and persistent
panels are constructed on first use. Shared assets and audio belong to the
application resource owner and outlive the Boot screen. Screen transitions and
common drawing live in `src/crimson/ui/` and `src/crimson/screens/chrome.py`.

`WorldState` owns simulation state. `DeterministicSession` adds mode timing,
ordered mode phases, and deterministic presentation planning. `WorldRuntime`
binds that simulation to the live camera, terrain and resource consumers.
`WorldRenderCtx` combines a frame with an immutable `ViewTransform` at draw time;
there is no second renderer-owned copy of the camera or world dimensions.

All five gameplay modes and replay initialize through `initialize_run`.
Demo/attract and debug views use `src/crimson/world/standalone_tick_harness.py`
for their separately configured sessions. See the [session contract](deterministic-step-pipeline.md)
and [startup contract](replay-run-start.md) for ordering requirements.

The [Zig port](zig-verifier.md) has its own native platform and product shell,
with a shared runtime for live play and replay tools.
