# Port review: simplification and behavioral correctness

Reviewed on 2026-09-05 at `9ec5ea665f275bd075ebaea9af819c6574058d6d`.

The port's basic direction is sound: explicit state, a shared deterministic session, recorded inputs, and headless execution are useful departures from the original globals. The strongest cleanup opportunity is around that core. Several adapters reconstruct data, copy ownership, or postpone decisions until the state they describe has already changed. Those costs are now producing observable bugs.

I found **eight actionable correctness findings**, including six reproduced with small executable probes. Two concern native behavior confirmed from original instructions; three concern unfinished network recovery. I recommend fixing the bounded gameplay/input problems first, then simplifying the tick boundary. A broad rewrite would make those changes harder to validate.

This report proposes changes; **no gameplay, test-suite, or networking implementation was edited**. The only additions are this report and its evidence files. The age or model provenance of a particular function is not treated as evidence that it is wrong.

## Scope and evidence

The main review covered the mature Python port: session/world ownership, tick scheduling, input conversion, presentation application, perk dispatch, selected weapon/bonus/creature paths, replay orchestration, and rollback/resync integration. Zig was checked selectively for corresponding behavior and useful design differences. This is not a line-by-line audit of all rendering, menus, quests, asset codecs, or the Zig port.

Native comparisons used the live `crimsonland.exe.bndb` database, recovered C under `tools/match/scratches`, and the repository's explicit float-parity rules. Binary Ninja's high-level view of `bonus_apply` contained only a declaration, so I checked its actual instructions. Native references below use function names and addresses rather than generated decompiler line numbers.

Evidence terminology:

- **Reproduced:** the checked-out implementation demonstrates the issue in [probes.py](/Users/banteg/dev/banteg/crimson/analysis/reviews/2026-09-05-port-review/probes.py), with results in [probe-results.json](/Users/banteg/dev/banteg/crimson/analysis/reviews/2026-09-05-port-review/probe-results.json).
- **Native verified:** original instructions establish the expected operation or guard; this does not mean the original executable was run during this review.
- **Code-path verified:** the production call chain or payload schema establishes the omission, without a live multiplayer experiment.

The original game was not played or recaptured, and no two-machine network session was run. The targeted existing tests passed: **148 total**. That establishes a passing baseline, not general parity or multiplayer readiness.

## Correctness findings

| ID | Priority | Finding | Affected implementation | Evidence |
| --- | --- | --- | --- | --- |
| B1 | P1 | Freeze skips native effects and RNG for same-tick kills | Python; same filter in Zig | Reproduced + native verified |
| B2 | P1 | Subsequent frame ticks lose control modes and held reload | Python live/LAN input | Reproduced |
| B3 | P2 | Input edges disappear on rendered frames with no simulation tick | Python local input | Reproduced |
| B4 | P2 | Quest completion sounds disappear or repeat across a tick batch | Python local gameplay | Reproduced |
| B5 | P2 | Man Bomb angles still use the wrong arithmetic precision | Python | Reproduced + native verified |
| B6 | P1 before netplay use | Python rollback requeues old inputs without restoring the world | Python rollback gameplay | Code-path verified |
| B7 | P1 before netplay use | Resync snapshots cannot restore authoritative game state | Python and Zig | Code-path verified |
| B8 | P1 before netplay use | Emitting local input deletes history needed for rollback/resends | Python rollback controller | Reproduced |

### B1. Freeze's tick-start corpse filter contradicts the native loop

[WorldState.step](/Users/banteg/dev/banteg/crimson/src/crimson/sim/world_state.py:326) snapshots dead creature indices before the tick. That set travels through bonus update/application and [gates shatter work](/Users/banteg/dev/banteg/crimson/src/crimson/bonuses/freeze.py:34) even though every dead active creature is deactivated.

The original `bonus_apply` (`0x00409890`, loop at `0x00409bbb–0x00409c3a`) checks the creature's **current active flag and current health**. For every qualifying corpse it performs eight shard-angle draws and one shatter-angle draw, calls the effect functions, then clears the active flag. There is no tick-start membership check. The port's additional lifecycle-threshold guard is also absent from this native loop. See [native-freeze.txt](/Users/banteg/dev/banteg/crimson/analysis/reviews/2026-09-05-port-review/native-freeze.txt).

**Reproduction:** one live creature is killed by a pistol projectile, then the player collects Freeze during the same `DeterministicSession.step_tick`. Current code records one death and one Freeze pickup but makes zero Freeze angle draws. Running the identical scenario with only the tick-start filter bypassed makes all nine angle draws. Including the effect helpers, the recorded RNG-call count changes from **119 to 212: 93 omitted draws**. Both runs remove the corpse.

This changes future random gameplay as well as the shatter appearance. It happens with `preserve_bugs=True`; it is not one of the documented default-mode corrections. [Zig carries the same two guards](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/bonuses.zig:473).

**Proposed fix:** use the native current-state guards, then remove the unnecessary tick-start set and its parameter plumbing. Treat delayed effect execution separately if any capture path still requires it. Validate a real same-tick kill/pickup capture and RNG trace; update the existing test that currently enshrines the tick-start filter.

### B2. Clearing edges also changes held controls and movement interpretation

[clear_input_edges](/Users/banteg/dev/banteg/crimson/src/crimson/local_input.py:142) reconstructs `PlayerInput` by hand. It omits `reload_down`, `move_mode`, and `aim_scheme`, resetting them to `False`, `None`, and `None`.

Both [LocalInputProvider](/Users/banteg/dev/banteg/crimson/src/crimson/sim/input_providers.py:119) and [LAN input capture](/Users/banteg/dev/banteg/crimson/src/crimson/modes/base_gameplay_mode.py:1732) use this for additional ticks in one rendered frame. At a 30 Hz render rate with a 60 Hz simulation, the second tick can therefore use different controls from the first.

**Reproduction:** an input with relative movement, keyboard aim, and held reload becomes static movement, mouse aim, and released reload after edge clearing. The resolved modes change because [gameplay's fallback logic](/Users/banteg/dev/banteg/crimson/src/crimson/gameplay.py:467) interprets absent mode fields differently. This can alter movement/aim and the manual-reload or alternate-weapon gates.

**Proposed fix:** copy the typed input with `msgspec.structs.replace`, changing only true edge fields. Explicitly classify the misleadingly named movement `*_pressed` fields: the interpreter populates them using held-key state. Test relative, static, mouse-point-click and keyboard/joystick aim across multiple ticks in a frame, including held reload. Replay packing already preserves the three omitted fields; the loss occurs before packing.

### B3. Zero-tick rendered frames discard pending button edges

[LocalInputProvider.begin_frame](/Users/banteg/dev/banteg/crimson/src/crimson/sim/input_providers.py:119) replaces the prior input frame unconditionally. The [frame pump](/Users/banteg/dev/banteg/crimson/src/crimson/sim/frame_pump.py:54) calls it even when the fixed-step clock requests zero ticks. Commands are retained separately, but button edges are not.

**Reproduction:** render frame one contains a fire press and requests zero ticks; frame two has no press and requests one tick. The first simulation tick receives `fire_pressed=False`. This affects short taps and edge-triggered behavior such as Anxious Loader, particularly when rendering faster than simulation.

**Proposed fix:** retain unconsumed edges until a simulation tick consumes them. Keep the latest held state/aim independently. A small edge latch is sufficient for the current boolean tick contract; an ordered event queue is only necessary if multiple transitions within one tick must be represented. Test different render partitions of the same input timeline, including pauses and no-tick frames.

### B4. Quest presentation reads the end of the batch for every tick

The session updates `QuestSpawnState.play_hit_sfx` and `play_completion_music` each tick. [build_post_apply_reaction](/Users/banteg/dev/banteg/crimson/src/crimson/sim/presentation_reactions.py:29) reads those mutable fields instead of facts saved in `TickResult`. [Local gameplay simulates the whole batch before applying it](/Users/banteg/dev/banteg/crimson/src/crimson/modes/base_gameplay_mode.py:1974), so every result sees the final tick's flags.

**Reproduction using two real quest-session ticks:**

- Completion timer starts at 810 ms: per-tick hit flags are `[true, false]`; deferred apply reads `[false, false]` and loses the stinger.
- Timer starts at 2001 ms: per-tick completion-music flags are `[true, false]`; deferred apply loses the music event.
- Timer starts at 790 ms: per-tick hit flags are `[false, true]`; deferred apply reads `[true, true]` and repeats it.

[QuestMode's production callback](/Users/banteg/dev/banteg/crimson/src/crimson/modes/quest_mode.py:336) uses this same mutable-state reader. Zig's live runner collects these transitions inside its tick loop, so this specific batching defect was not found there.

**Proposed fix:** put the quest sound/music requests in that tick's immutable output. The consumer should need only the output to play them. Also review mode-stop decisions at this boundary: local batches finish simulating before a stop request is evaluated. That is an additional risk to investigate, not a separately reproduced finding here.

### B5. Man Bomb still uses double-precision angles

[tick_man_bomb](/Users/banteg/dev/banteg/crimson/src/crimson/perks/impl/man_bomb.py:34) computes `roll * 0.01 + index * (math.pi / 4) - 0.25` in Python doubles, narrowing only at projectile spawn.

In native `player_update` (`0x004136b0`, angle instructions at `0x0041394d–0x00413966`), each multiply/add/subtract follows the gameplay x87 PC24 behavior and uses stored float constants, including `0.785398185f`. See [native-man-bomb.txt](/Users/banteg/dev/banteg/crimson/analysis/reviews/2026-09-05-port-review/native-man-bomb.txt).

**Reproduction:** a real `player_update` with Man Bomb ready and zero jitter produces these differing stored projectile-angle bits:

| Projectile index | Port | Native expression |
| --- | --- | --- |
| 5 | `0x406b53d1` | `0x406b53d2` |
| 7 | `0x40a7eddf` | `0x40a7ede0` |

The existing test checks projectile count, types, ownership, and RNG callers but not these angle values. This is a demonstrated numeric parity error; a later collision or score difference was not measured.

**Proposed fix:** use `NATIVE_QUARTER_PI` and the existing PC24 arithmetic helpers in native instruction order. Add exact stored-angle checks with several jitter values. Zig uses an f32 expression here; do not copy the Python formula into it or assume the same defect without checking its compiled arithmetic.

### B6. Python rollback changes the input queue without rolling back simulation

[RollbackRuntime._apply_rollback_from](/Users/banteg/dev/banteg/crimson/src/crimson/net/rollback_runtime.py:584) finds a snapshot, rebuilds emitted frames, puts them back in the queue, and logs `rollback_applied`. The gameplay consumer [only logs the rollback request](/Users/banteg/dev/banteg/crimson/src/crimson/modes/base_gameplay_mode.py:1255). It restores state only for the separate resync path.

The LAN input provider then [labels each popped frame with the current runner tick](/Users/banteg/dev/banteg/crimson/src/crimson/modes/base_gameplay_mode.py:233). Replayed old inputs can therefore advance the already-current world, rather than reconstructing the corrected history. Queue/controller tests cannot establish that this restores gameplay.

**Proposed fix:** one recovery owner must restore the state before the correction, rebuild through the former head, replace affected history/checkpoints, and suppress duplicate presentation/persistence effects. Keep the operation atomic with respect to normal stepping. Zig's local runner snapshots and restoration are a useful existing reference, though their existence is not proof of network resync correctness.

This is a feature-completeness blocker already acknowledged in part by the deterministic-pipeline documentation; the report establishes the concrete production consequence rather than treating it as a newly discovered undocumented native quirk.

### B7. Network resync transports mode counters, not a recoverable world

[ModeStateSnapshotV2](/Users/banteg/dev/banteg/crimson/src/crimson/net/rollback_resync_v5.py:34) contains mode timing/spawn metadata and optional recorder counters. It does not contain player state, creature/projectile/effect pools, the authoritative RNG, bonus state, or most perk state. [Survival's apply method](/Users/banteg/dev/banteg/crimson/src/crimson/modes/survival_mode.py:413) restores only elapsed time, stage, and spawn cooldown; even transmitted `perk_pending_count` is not applied there.

Zig's [modeSnapshotFromRunner/applyModeSnapshotToRunner](/Users/banteg/dev/banteg/crimson/crimson-zig/src/net/rollback_live_bridge.zig:75) have the same limitation. [Its actual resync consumer](/Users/banteg/dev/banteg/crimson/crimson-zig/src/net/rollback_live_session.zig:167) applies that payload and commits recovery. The complete local `LiveRunnerSnapshot` is a different mechanism and is not the transferred resync payload.

Two peers with different health, enemies, or RNG state will retain those differences after a successful mode-snapshot exchange. Existing tests mainly verify the metadata, transport completion, and resumed input flow.

**Proposed fix:** define a complete deterministic session snapshot, or a replay-from-common-state recovery protocol. Include the native-parity effect state that influences later RNG allocation/consumption, not just obvious combat entities. Prove recovery by deliberately diverging peers, restoring, then comparing full state and several subsequent corrected ticks. Audit cursor rewind and recorder truncation as part of the same work.

### B8. Local input retention is tied to the emission cursor

[RollbackController.queue_local_input](/Users/banteg/dev/banteg/crimson/src/crimson/net/rollback.py:70) sets the oldest retained tick to at least `_next_emit_tick`. It deletes already-emitted local inputs, even though they are precisely the history needed for rollback and packet redundancy.

**Reproduction:** after emitting four distinct local inputs with zero input delay, rebuilding ticks 1–3 yields neutral input for ticks 1 and 2 instead of their original values. The fourth outgoing packet contains only tick 3. With a positive delay the retained window is still governed by emission rather than the configured rollback/resend history.

**Proposed fix:** retain local history for the configured horizon independently of emission, with resend selection and rollback retention made explicit. [Zig already uses the history-based lower bound](/Users/banteg/dev/banteg/crimson/crimson-zig/src/net/rollback.zig:87) and has a regression test for resending emitted inputs. Port the behavioral contract and test it through simulation recovery, not just the controller.

## Simplification proposals

### S1. Make one tick result complete, then shorten its application path

**Highest value; medium risk.** Today the useful input/session contract is surrounded by `TickResult -> DeterministicSessionTick -> DeterministicStepResult`, then `PresentationTickOutput`, post-apply reactions, batch outcomes, and mode-specific adapters. The problem is partly semantic: some wrappers describe the tick, while others must reread the current world to finish describing it. B4 is the resulting failure.

Have the session return one tick output containing its timing, events, complete presentation requests, and mode transition facts. Keep replay/network identifiers in a small driver envelope if needed. Apply each tick's bookkeeping and stop decision while that tick is current; audio/render work can still be batched from immutable outputs. Put profiling durations outside the deterministic payload.

This can remove reaction reconstruction and several one-method apply adapters without merging local input polling, replay preludes/postludes, and network availability into one complicated provider. Those sources have legitimately different timing contracts.

**Validation:** compare the same inputs under 120/60/30 Hz render partitions; compare all simulation checkpoints and ordered presentation requests; include quest completion and death during a multi-tick frame. Retain the current original-capture prelude/postlude tests.

### S2. Give authoritative state one owner

**High value; medium risk.** [SimWorldState](/Users/banteg/dev/banteg/crimson/src/crimson/world/sim_world_state.py:162) stores `world_state` plus aliases to its `state`, `players`, `creatures`, and `spawn_env`. Configuration and `game_tune_started` are also copied among the session, world wrapper, and runtime. Reset/load paths must repair those relationships manually.

Keep one authoritative world/session aggregate. Expose child references as properties rather than independently assignable fields; keep HUD/camera/presentation caches in a separate view state. Make ownership of RNG, mode state, and parity-affecting settings explicit. Move `GameplayState` out of the large gameplay implementation module: the [runtime `GameplayState = object` type alias](/Users/banteg/dev/banteg/crimson/src/crimson/sim/state_types.py:79) is evidence of the current import-cycle pressure, not a useful domain abstraction.

This gives snapshot/recovery work a concrete boundary and preserves testing through ordinary state construction. Avoid simply serializing the current cyclic object graph, which includes services and aliases.

For Zig, use accessors for slices into owned storage where practical. [rebindInternalPointers](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/session.zig:266) and snapshot rebinding currently maintain interior pointers after value copies. Removing derivable stored references would reduce that maintenance burden. No dangling-pointer defect was established in this review.

**Validation:** reset/load identity invariants, snapshot/restore followed by equal future ticks, and second-run residue tests. Preserve intentional native residue instead of replacing all resets with fresh objects by default.

### S3. Replace one-off registries with direct ordered code

**Good first cleanup; low risk when expressions stay unchanged.** The [weapon clip modifier layer](/Users/banteg/dev/banteg/crimson/src/crimson/weapon_runtime/assign.py:19) creates a context, callable alias, two handlers, a tuple, and a dispatch loop for two short conditionals. A helper returning the adjusted clip size can express that directly. The [single-entry Poison Bullets hook tuple](/Users/banteg/dev/banteg/crimson/src/crimson/projectiles/runtime/behaviors.py:66) is another small candidate.

Keep the bonus-ID handler table and projectile-type rule table: they express real variation and make the code easier to inspect. Keep per-perk implementation files if their discoverability is useful. As a second step, consider explicit ordered tuples per native phase instead of [one optional-field `PerkHooks` aggregate](/Users/banteg/dev/banteg/crimson/src/crimson/perks/runtime/hook_types.py:48) projected into several registries. The phase order would then be readable at the phase entry point. That larger change has less immediate payoff than the tiny registries.

**Validation:** unchanged exact outputs and RNG-call order. Do not reorder native phases or simplify PC24 expressions while removing dispatch scaffolding.

### S4. Make full damage semantics mandatory at the gameplay boundary

**High testing value; medium risk.** [CreatureDamageRuntime](/Users/banteg/dev/banteg/crimson/src/crimson/creatures/damage_runtime.py:17) has default no-op methods. `DirectCreatureDamageRuntime` mostly subtracts HP and is selected automatically when a runtime is absent in [projectile stepping](/Users/banteg/dev/banteg/crimson/src/crimson/projectiles/runtime/projectile_pool.py:206), secondary projectiles, and particles. Tests can exercise a cheaper semantic path that omits death rewards, side effects, ownership, and RNG sequencing.

Keep pure damage calculations easy to test, but require the real damage resolver for integrated gameplay. Use explicit recording fakes in unit tests rather than production fallbacks that silently mean something different. Prefer a small typed callback/required interface to a family of instantiable no-op runtime classes.

The important constraint is **synchronous native ordering**: a lethal hit can run death handling, then damage follow-up RNG, before its caller continues. Do not replace this with a generic end-of-tick death sweep. Direct health writes from some perks/projectiles also intentionally bypass parts of normal damage handling.

**Validation:** test both pure formulas and full session paths for direct hits, corpse hits, explosion kills, Final Revenge, and bonus suppression. Compare the interleaved RNG/events, not only final HP.

### S5. Treat input conversion as a small explicit boundary

**High value; low-to-medium risk.** B2 and B3 can be fixed with a typed copy and an edge latch, preserving the existing input object. After that, clarify names for held movement controls and keep a single packing/unpacking contract. The present `move_mode=None` inference should be confined to older/capture data that actually needs it; live input already knows the selected modes.

Validate/normalize once at the source boundary, then pass typed values through the domain. [TickRunner](/Users/banteg/dev/banteg/crimson/src/crimson/sim/tick_runner.py:52), session stepping, and world stepping currently repeat tuple/list reconstruction and normalization. Remove demonstrably redundant conversions, while retaining actual wire validation and all float32/native rounding boundaries.

Do not turn this into a generic event-bus redesign. A canonical input plus pending edges and explicit commands covers the current requirements.

### S6. Extract phases from long gameplay functions without hiding their order

**Useful after the boundary work; medium risk.** The large functions are not inherently wrong, but several combine distinct jobs:

| Function | Current lines | Useful decomposition |
| --- | ---: | --- |
| [player_update](/Users/banteg/dev/banteg/crimson/src/crimson/gameplay.py:630) | 505 | Control dispatch/movement, reload transition, aim update, firing gates |
| [CreaturePool.update](/Users/banteg/dev/banteg/crimson/src/crimson/creatures/runtime.py:964) | 499 | Corpse lifecycle, target selection/AI, movement/contact, spawn follow-up |
| [SecondaryProjectilePool.step](/Users/banteg/dev/banteg/crimson/src/crimson/projectiles/runtime/secondary_pool.py:182) | 459 | Target/steering, movement, detonation and follow-up |

Keep the top-level function as a visible ordered list of those native phases. Use concrete state and a few narrowly scoped arguments, not more feature registries or a universal context object. Separate moving code from changing arithmetic or guards. Preserve pool iteration order, slot reuse, mutations during iteration, and immediate callbacks.

One additional vocabulary cleanup to consider later is `OwnerRef.local_host`: it represents the native `-100` ownership convention used with friendly fire disabled, while a separate `owner_player_index` often identifies the shooter. Naming collision allegiance separately from shooter attribution would make multiplayer reasoning easier. Preserve the exact legacy encoding and attribution behavior during any such change.

## What I would deliberately keep

- **The deterministic session and headless entry point.** They let tests exercise the same simulation as gameplay and replays.
- **Deterministic presentation planning.** Native sound/effect paths consume the shared RNG. Moving those draws into the renderer, or dropping them in headless mode, would break parity.
- **Explicit PC24/f32 helpers and unusual constants.** B5 shows why ordinary-looking arithmetic is not always equivalent.
- **Spawn plans where they separate construction from materialization.** They make scripted content testable; runtime side effects must still occur at the evidenced point.
- **Stable pool indices/generations and synchronous damage callbacks.** Replacing pools with convenient filtered lists or deferring all events would change observable native ordering.
- **Explicit `preserve_bugs` behavior.** Documented default-mode improvements should not be reported as parity defects. The findings above were checked against that distinction.

## Suggested sequence for later fixes

1. **Bounded correctness changes:** B2/B3 input handling, B1 Freeze, B5 Man Bomb. Give each independent evidence and a focused regression. Freeze needs a capture follow-up because it changes the shared RNG stream substantially.
2. **Tick-output cutover:** B4 plus S1. Make quest presentation and mode-stop facts belong to the producing tick, migrate consumers, then delete the superseded adapters.
3. **Small structural cleanup:** S3's tiny registries, followed by the required damage interface in S4. Keep the broader perk registry unless simplifying it pays off in actual call sites.
4. **State ownership and network closure:** S2 plus B6–B8. Reuse useful Zig work, define a complete snapshot contract, and require two-peer state convergence after impaired input delivery and resync before treating netplay as validated.
5. **Local phase extraction:** S6, one subsystem at a time, with unchanged parity traces.

## Reproduction and validation record

From the checkout root, the review probes can be rerun with:

```sh
PYTHONPATH=. UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python analysis/reviews/2026-09-05-port-review/probes.py
```

The probes assert that the reported discrepancies exist at the reviewed commit; they are evidence scripts, not proposed permanent tests. Freeze's comparison temporarily bypasses only the tick-start filter in memory. It does not edit the implementation or claim a recorded original-game result. File hashes and the reviewed commit are recorded in [evidence.json](/Users/banteg/dev/banteg/crimson/analysis/reviews/2026-09-05-port-review/evidence.json).

Existing tests run:

- **107 passed:** input-provider semantics, tick-runner hook order, player update, Freeze bonus, runtime resync/mode selection, and snapshot ring tests.
- **22 passed:** rollback core/runtime, mode snapshot application, step-pipeline parity, and runner presentation regressions.
- **19 passed:** capture parity regressions, including fresh Python/Zig trace comparisons. The first attempt failed during Zig fixture setup because its default cache was unwritable; rerunning with `ZIG_GLOBAL_CACHE_DIR=/private/tmp/crimson-review-zig-cache` passed. Zig version was `0.16.0`.

Full-suite validation, new original-game captures, visual playtesting, and live multiplayer testing remain work for the chosen fixes. No commits were made.
