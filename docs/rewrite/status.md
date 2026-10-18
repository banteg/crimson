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

See [setup](../contributor/setup.md) for invocation. This page describes
supported scope, not a claim that every native branch has been verified.

## Evidence and its limits

| Check | What it establishes |
| --- | --- |
| `tests/replay/test_live_run_start.py` | Live mode startup and recorder/playback agree on complete session state, including non-default settings. |
| `tests/modes/test_live_replay_invariant.py` | Live tick batching, controller input, and perk commands replay to identical complete session state. |
| `tests/render/test_ground_dump_fixtures.py` | Captured terrain images agree within the test's documented tolerances; requires assets and a display. |
| `crimson-core/checks/gate.py` | The recovered core agrees with Python's complete run results on the gate's replay fixtures and bot corpus under both bug policies, for one or two players in Rush, Survival and Quests with every control scheme. Typ-o, Tutorial and three or four players are outside the verifier's scope; the service verifies one- and two-player runs. |
| `tests/native_oracle/` | Ported functions agree bit for bit with the original code run under the [native execution oracle](../verification/differential-testing/native-oracle.md) on the tested cases. |

`just check` runs the repository gates. Skipped display-dependent tests do not
prove rendering parity, and startup smoke tests do not replace a full product
walkthrough. A checkpoint samples only part of the state; use complete session
digests for same-build port regression comparisons. Native parity claims need
address-keyed source evidence, a native-oracle test, or the core gate. See [evidence records](../verification/evidence-ledger/index.md).

## Intentional differences

- `--preserve-bugs` selects the documented [native quirks](original-bugs.md).
- Exact multiplayer parity targets the native 1/2-player paths. The 3/4-player
  extension must preserve those outcomes; see [local multiplayer](local-multiplayer.md).
- Rendering has explicit options and sampling differences; see [terrain](terrain.md)
  and [beam rendering](beam-rendering.md).
- Mods are out of scope in every version: the original's mods are DLL plugins, so the port and the web and
  native clients offer no Mods entry.
- The original's Other Games advertisement flows and its
  [online scores](../crimsonland-exe/online-scores.md) client for
  `scores.crimsonland.com` are out of scope. Ranked runs go to the crimson.land
  leaderboard under the [ranked rules](ranked-rules.md).
- The Python port has no network play. Online co-op is crimson-core's: two players in the browser
  ([crimson.land/play](https://crimson.land/play/), joined by an invite link) with rollback, their runs
  ranked on the co-op boards; see the [network co-op specification](network-coop.md).

Outstanding native timing, precision, input-scheme and visual differences should
be recorded with a reproducer and evidence. A completed implementation plan or a
green generated corpus is not a list of all remaining parity gaps.
