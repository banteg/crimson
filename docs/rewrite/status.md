---
tags:
  - rewrite
  - parity
---

# Coverage and scope

The Python port supports boot, menus, all five gameplay modes, game-over and
quest results, progression, high scores, options/controls, audio, terrain and
world rendering. Quest content covers tiers 1–5. Local co-op supports 2–4 players
in Survival, Rush and Quests; Typ-o and Tutorial use their own mode rules.
All five modes share run initialization and deterministic replay execution.

See [setup](../contributor/setup.md) for invocation and the [Zig port](zig-verifier.md)
for its desktop and tooling surfaces. This page describes supported scope, not a
claim that every native branch has been verified.

## Evidence and its limits

| Check | What it establishes |
| --- | --- |
| `tests/replay/test_live_run_start.py` | Live mode startup and recorder/playback agree on complete session state, including non-default settings. |
| `tests/sim/test_step_pipeline_parity.py` | Live tick batching and replay/headless paths preserve tested timing, input and state behavior. |
| `tests/render/test_ground_dump_fixtures.py` | Captured terrain images agree within the test's documented tolerances; requires assets and a display. |
| `tests/replay/cli/test_zig_corpus.py` | Native tools handle the generated current-format corpus across the five modes and invalid inputs. |
| `tests/grim/test_zig_window_cli.py` | Native desktop installation, help and non-rendering direct-start construction work. |
| Current original/candidate CDT comparisons | The recorded runs agree through the reported tick/channel span. |

`just check` runs the repository gates. Skipped display-dependent tests do not
prove rendering parity, and startup smoke tests do not replace a full product
walkthrough. A checkpoint samples only part of the state; use complete session
digests for same-build port regression comparisons. Native parity claims need
address-keyed source evidence or a current, healthy capture with identified
artifacts and comparison results. See [evidence records](../verification/evidence-ledger/index.md).

## Intentional differences

- `--preserve-bugs` selects the documented [native quirks](original-bugs.md).
- Exact multiplayer parity targets the native 1/2-player paths. The 3/4-player
  extension must preserve those outcomes; see [local multiplayer](local-multiplayer.md).
- Rendering has explicit options and sampling differences; see [terrain](terrain.md)
  and [beam rendering](beam-rendering.md).
- Mods are discovered and displayed, but native DLL plugin execution is out of scope.
- Other Games advertisement/runtime flows and native online-score submission are out of scope.
- Custom network play was removed and is [deferred](netplay.md).

Outstanding native timing, precision, input-scheme and visual differences should
be recorded with a reproducer and evidence. A completed implementation plan or a
green generated corpus is not a list of all remaining parity gaps.
