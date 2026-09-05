# Systems review after the port and screen cleanups

Implemented: see [FIXES.md](FIXES.md) for commits and validation. The findings and baseline results below describe the pre-fix code.

Reviewed on 2026-09-05 at `defec436afc838affac470d84e9ab90707693ef8`.

The next substantial improvement is to make live play and replay share both **run initialization and command execution**, in addition to the simulation step they already share. Two reproduced divergences sit on those boundaries. Presentation still has one mutable-state leak, and the camera simulation has a separate native timing error.

This is a report, with executable evidence. No production code or existing tests were changed. Screens and the removed networking implementation are outside this pass. The review concentrates on Python; corresponding Zig behavior has not been established in this pass.

## Findings and proposed work

### R1. One run initializer for live play and replay — confirmed bug

[Tutorial startup](/Users/banteg/dev/banteg/crimson/src/crimson/modes/tutorial_mode.py:115) explicitly assigns the normal pistol before building its session. [Replay startup](/Users/banteg/dev/banteg/crimson/src/crimson/replay/driver/playback_driver.py:186) resets the player, and [the shared Tutorial builder](/Users/banteg/dev/banteg/crimson/src/crimson/sim/session_builders.py:151) never makes that assignment.

The probe opens the actual Tutorial mode with only resource loading and terrain presentation stubbed, records an input, and runs the actual playback driver:

| State | Live | Replay |
| --- | --- | --- |
| Initial ammo / clip size | 12 / 12 | 10 / 10 |
| Initial shot cooldown | 0 | 0.8 seconds |
| Shots after first firing tick | 1 | 0 |
| RNG after that tick | 436623559 | 149091596 |

This is already a replay correctness failure, before considering the later tutorial stages.

**Proposal:** one typed run specification and initializer should produce the prepared world, mode session, and terrain setup. Live play and playback supply inputs to that initializer; the recorder serializes the same specification. Move weapon assignment, terrain RNG advancement, status binding, and mode initialization into that boundary in their existing required order.

Make the fresh-run versus imported-native-residue policy explicit there. The current player reset helper preserves selected old fields, but production reset callers pass newly built empty player lists. That inconsistency is a contract cleanup, not evidence that port runs should inherit previous-run garbage: fresh port runs are intentional in the replay format.

**Validation:** compare initial state and recorded playback through real mode startup for every supported mode, including the first firing tick and startup RNG/SFX.

### R2. Record commands without changing their execution phase — confirmed bug

[Live session stepping](/Users/banteg/dev/banteg/crimson/src/crimson/sim/sessions.py:453) calculates timing before executing queued perk commands. [The recorder](/Users/banteg/dev/banteg/crimson/src/crimson/replay/recorder.py:73) moves those commands into the replay prelude. [Playback](/Users/banteg/dev/banteg/crimson/src/crimson/replay/driver/playback_driver.py:409) executes that prelude before entering the session and calculating timing.

Starting from identical prepared Survival worlds with Reflex Boosted available, the same recorded pick and movement input give:

| Result of the pick tick | Live command path | Recorded playback path |
| --- | --- | --- |
| Simulation delta | 0.01666666753590107 | 0.015000000596046448 |
| Elapsed milliseconds | 16 | 15 |
| Player X | 512.0045166015625 | 512.0032958984375 |

**Proposal:** centralize ordered command application and timing derivation. Both callers should execute the same phase-aware tick operation. Serialization should preserve its meaning. Keep the separately observed native capture prelude/postlude boundaries explicit; merely moving every operation earlier would erase information those captures need.

**Validation:** record and replay perk picks that change timing, ordered multiple picks, and the existing native prelude/postlude RNG cases. Decide replay version handling as part of the semantic change.

### R3. Finish the deterministic presentation boundary and simplify audio — confirmed bug

[Presentation application](/Users/banteg/dev/banteg/crimson/src/crimson/sim/batch_apply.py:81) runs after a batch, but [audio routing](/Users/banteg/dev/banteg/crimson/src/crimson/audio_router.py:45) obtains the Reflex Boost timer from the current world. The sound request contains its SFX ID but not the timing context needed to play it.

With two real simulation ticks spanning bonus expiry, immediate application passes `0.00833333283662796` for the first tick's sound. Batched application passes the final timer, `-0.00823611207306385`. Simulation RNG is identical (`303570046`), but [pitch selection](/Users/banteg/dev/banteg/crimson/src/grim/sfx.py:63) takes a different branch.

There is also redundant ownership: `AudioBridge` wraps `AudioRouter`, which retains `handle_player_audio` and `play_hit_sfx` decision logic duplicated in the deterministic presentation planner. Those two methods have test callers and no production callers in the current source tree.

**Proposal:** capture the sound timing context when the event is decided, and let one audio consumer apply those requests. Delete the unused decision paths and move their behavioral tests onto the planner/consumer path. Inspect camera application under the same rule: it too reads final batch state for every output, and preserving camera position when all players are dead makes it stateful. The audio defect is reproduced; a full camera batching reproduction is not claimed here.

**Validation:** run the same ticks in different frame partitions and compare the emitted sound IDs and pitch inputs, including prelude sounds and bonus pickup/expiry boundaries.

### R4. Camera shake must use the latched time-scale flag — confirmed native mismatch

[The port](/Users/banteg/dev/banteg/crimson/src/crimson/camera.py:56) derives its next pulse interval from `bonuses.reflex_boost > 0`. [Recovered camera_update](/Users/banteg/dev/banteg/crimson/tools/match/scratches/camera_update/scratch.cpp:19) checks `time_scale_active`. These are different values: [the world step](/Users/banteg/dev/banteg/crimson/src/crimson/sim/world_state.py:430) deliberately latches the flag before decrementing the bonus timer.

The real-session probe reaches the next tick with `time_scale_active=True`, bonus timer `-0.0065500009804964066`, and a pending shake pulse. The port resets the interval to `0.1`; the recovered native branch selects `0.06f`. Each subsequent pulse consumes six authoritative RNG draws, so this is simulation timing, not just a visual preference.

**Proposal:** use the authoritative latch and preserve native numeric operations. Add expiry-boundary coverage. The existing camera tests only exercise cases where the bonus timer agrees with the intended flag; the current test for the short interval does not set the latch.

The native evidence here is the checked-in recovered source and its matching notes, not a newly executed original-game capture. The notes' broad statement that the port preserves the reflex interval needs narrowing or correction with the fix.

### R5. Give persistence one atomic file replacement boundary — reproduced failure behavior

[High-score saving](/Users/banteg/dev/banteg/crimson/src/crimson/persistence/highscores.py:411) opens the destination with `wb` before encoding its records. A deliberately injected encoding exception turns a valid 76-byte score file into an empty file. The next read silently yields no records. This is fault-injection evidence; no naturally occurring encoder failure was observed.

[Status saving](/Users/banteg/dev/banteg/crimson/src/crimson/persistence/save_status.py:304) and [configuration saving](/Users/banteg/dev/banteg/crimson/src/grim/config.py:264) encode before writing, but still overwrite the destination directly and can lose the old file on an interrupted write.

**Proposal:** encode completely, write a temporary file beside the destination, then atomically replace it. Reuse that small IO helper for user-owned saves, while keeping the native binary codecs separate. Clear dirty state only after success.

**Validation:** inject encoding and write failures and verify the previous file remains readable and byte-identical; retain existing binary-format round trips.

### R6. Strengthen the replay verification oracle — demonstrated coverage gap

[Replay checkpoints](/Users/banteg/dev/banteg/crimson/src/crimson/replay/checkpoints.py:243) summarize selected state. The probe changes shot cooldown, camera timer/pulses, and an inactive creature slot's HP. The checkpoint remains equal and `compare_checkpoints(...).ok` remains true.

This is a limitation of a deliberately partial schema, not a comparison-function bug. It matters when a green verification result is used to justify a simulation refactor: omitted state can affect later ticks, and inactive pool residue is part of the native model.

**Proposal:** add a canonical digest of the complete deterministic session state for port-to-port tests, alongside the existing readable checkpoints and native capture comparisons. Cover mode timers, all player/weapon fields, pool contents and cursors, RNG, and parity-relevant effect state. A recoverable snapshot format can build on that later; it need not be part of this cleanup.

Add real live-record-playback tests and frame-partition tests. Comparing two invocations of the same replay driver cannot detect R1 or R2. Exclude filesystem paths, resources, and profiling metadata from deterministic state comparison.

### R7. Express perk phases directly — structural simplification

[The manifest](/Users/banteg/dev/banteg/crimson/src/crimson/perks/runtime/manifest.py:34) puts 24 heterogeneous hook bundles in one global order, then filters them into five dispatch collections. In the current implementation, the world-delta collection has one function (Reflex Boosted), and the player-death collection has one function (Final Revenge).

**Proposal:** call those single implementations directly. Keep the genuinely useful perk-ID-to-apply-handler mapping. Express the ordered player-tick and effect phases as explicit calls or explicit phase-local tuples, preserving order and the per-perk implementation modules. This removes the optional-field hook envelope and makes native execution order visible at its actual call site.

Require creature and FX context for production effect phases that use them; optional context currently permits shortened behavior, including skipped RNG consumption. Test with real empty pools/queues when the intended world is empty. No production missing-context failure was reproduced in this pass.

## Evidence and validation

[probes.py](/Users/banteg/dev/banteg/crimson/analysis/reviews/2026-09-05-systems-review/probes.py) reproduces the observations above; [probe-results.json](/Users/banteg/dev/banteg/crimson/analysis/reviews/2026-09-05-systems-review/probe-results.json) records the results. Run from the repository root:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python analysis/reviews/2026-09-05-systems-review/probes.py
```

The probe substitutes external resource loading and audio playback, but uses real mode initialization, sessions, recording, playback, checkpoint comparison, and score-file IO. Perk availability is seeded identically in both worlds to isolate the command boundary. Save fault injection touches only a temporary directory.

**127 existing targeted tests passed:** Tutorial mode/replay, Survival replay, presentation reactions, replay codec, camera shake, world audio, game-tune triggering, world reset, and Reflex Boost pitch. Their success alongside these reproductions identifies missing coverage; it does not establish parity. No full repository gate, Zig run, interactive playtest, or original-game capture was performed for this report.

Recommended order: fix R1, R2, and R4 in separate focused commits with cross-path regression coverage; finish R3's presentation/audio cutover; make saves atomic; then introduce the stronger state oracle before the perk-phase cleanup. Keep the broader initializer refactor separate from its first Tutorial fix so each commit remains reviewable.
