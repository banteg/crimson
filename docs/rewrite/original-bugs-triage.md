---
tags:
  - rewrite
---

# Original bug triage for rules 2

Reviewed against `c0565b0b4e74c9aed422f23ddd9328027967cbc0`, the existing
41-entry bug ledger, recovered 1.9.93 sources, Python behavior, and portable
core adaptations. T01–T68 refer to the supplied `ORIGINAL-BUGS-TRIAGE.md`
catalog. That catalog is a candidate list, not evidence of 68 independently
verified, reachable, unfixed defects. Several entries contain multiple claims
with different dispositions. This review does not authorize every proposed fix.

The [original-bugs ledger](original-bugs.md) records implemented policy.
This document records recommendations and unresolved decisions.

## Selected rules-2 bundle

Implemented here in Python and the recovered-core patches, behind the bug policy:

1. **[Exact-zero reload completion](https://github.com/banteg/crimson/issues/827)**: finish a positive reload at `<= 0`, using
   the scaled step. This completes ledger #5; it is not a second independent
   Stationary Reloader fix.
2. **[Jinxed corpse rewards](https://github.com/banteg/crimson/issues/828)** (ledger #42): reject dead/dying slots using the
   existing ten-retry budget. Keep the accident, cooldown, base XP, and no-drop
   semantics. Both positive-HP dying bodies and nonpositive-HP slots are rejected.

The high-priority additions below are now implemented in Python and core adapters.
The medium-priority rows remain follow-up proposals. Planning tracker:
[#829](https://github.com/banteg/crimson/issues/829).

| Priority | Candidate | Default policy | Main tradeoff |
| --- | --- | --- | --- |
| High | [T22 Alternate Weapon](https://github.com/banteg/crimson/issues/822) | Each player owns their swap cooldown; determine fire eligibility after swapping, including the 0.1-second swap delay. Ordinary co-op offers still exclude this perk; the reachable readiness fix benefits solo play. | Requires co-op state/snapshot transport changes; preserve the old global path for original rules. |
| High | [C01 Fire Cough / Hot Tempered co-op intervals](https://github.com/banteg/crimson/issues/821) | Give each player their own next randomized trigger interval, alongside their existing elapsed timer. | Removes cross-player rescheduling; update snapshot/rollback state and keep the original shared thresholds under `preserve_bugs`. |
| High | [T67 negative health in quest scoring](https://github.com/banteg/crimson/issues/823) | Count a dead player's health as zero for the life bonus, for every seat. | Changes ranked co-op times; update the shared result calculation and recovered game/results paths together. |
| High | [T11 rocket duplicate deaths](https://github.com/banteg/crimson/issues/824) | A lethal AoE hit awards XP, drops, and split children exactly once. Retain intentional impact FX separately. | Rockets lose accidental duplicate XP/drops, and splitter kills create fewer children. This is a real economy change. |
| High | [T33 Shock Chain corpse targeting](https://github.com/banteg/crimson/issues/825) | Subsequent links require a living target just as the initial link does; handle no target explicitly. | Makes the bonus more reliable and changes link/RNG sequences. |
| High | [T26/T27 exact-zero DoT deaths](https://github.com/banteg/crimson/issues/826) | Treat zero HP as lethal in Plague and Radioactive, retaining each source's existing reward policy; stop post-death attacks. | Ledger #18 covers player damage only. Radioactive's no-drop/base-XP behavior should remain intentional. |
| Medium | T09 Shrinkifier / T43 Breathing Room | Mark their special deaths consistently so later hits cannot award a second death or treat cleared creatures as living. | Keep Breathing Room's intentional no-XP clear. Do not route every special death through the ordinary reward handler. |
| Medium | T48 Pistol + My Favourite Weapon | Skip forced weapon-drop conversion when the perk prohibits weapon drops, then run the ordinary drop path. | Restores bonus opportunities; preserve ordinary suppression and draw order on unaffected branches. |
| Adopted extension | T18 Fire Bullets pellet metadata | Rules 2: six Gauss Shotgun and five Multi-Plasma Fire Bullets, with normal multi-pellet cooldowns. | Explicit consistency decision; preserve legacy counts/cadence in rules 1 and original mode. Implemented in the final stack layer (#832). |
| Medium | T06/T07 Splitter ownership and collision | Separate player attribution from the last creature to exclude; search beyond an excluded overlap. | Do not fix by simply replacing the overloaded owner ID: that can immediately re-hit the parent creature and change splitting. |
| Medium | T25 Plaguebearer neighbor selection | Search for an eligible infection interaction, skipping self, dead slots, and neighbors that cannot exchange infection. | A broad all-neighbor spread would be a larger buff. Preserve the cadence, HP threshold, infection budget, and one-interaction policy unless deliberately redesigned. |

The impact-aligned death slide in [#818](https://github.com/banteg/crimson/issues/818)
is implemented in this batch with T02's cosine correction. It changes collision positions
while bodies collapse, so it is a simulation change even though its motivation
is visual. Preserve the original slide distance and timing initially. Ledger #49 specifies lethal impulses, Nuke direction, zero-length hits,
spawners, and splitter-child inheritance.

Do **not** automatically bundle the piercing-pool nerf in
[#820](https://github.com/banteg/crimson/issues/820), a fivefold flamer-range
change, quest-wave redesigns, or removal of shared co-op pickups. Those change
established balance or player-facing rules substantially and need a separate
decision. A rules bump permits them technically; it does not establish that they
make the game better.

## Strongest validation results

Exact-zero reload and Jinxed eligibility were first reproduced against the original 1.9.93
executable under Unicorn using the repository's native oracle. These were
controlled function/fragment executions, not observations from an interactive
original-game session:

- Jinxed selected an active creature at -10 HP: player XP rose from 100 to 200.
- The original reload fragment decremented 0.1 seconds in five 0.02-second
  frames to exactly zero with no refill. A full Pulse Gun reload reproduces
  the same result through the Python player update.

Additional controlled probes below used the unmodified candidate paths in
Python at the reviewed base, checked against their recovered source. They are
not new native-executable confirmations:

| ID | Probe and result |
| --- | --- |
| T11 | Expanding detonation, 1-HP victim worth 100 XP: **200 XP and two death events**. A splitter victim produces **four living children**. Rush mode suppressed unrelated bonus-roll RNG. |
| T22 | Two Assault Rifle players with Pistol alternates tap swap in the same tick: weapons become **Pistol / Assault Rifle**. Separate earlier probe: ready Pistol can swap-fire an empty Gauss with 1.5 seconds of reload and 0.5 seconds of cooldown left. |
| T18 | Normal / Fire Bullets projectile counts: **Gauss Shotgun 6 / 1**, **Multi-Plasma 5 / 3**. |
| T25 | Three neighboring slots: healthy 200-HP blocker, healthy 100-HP target, infected 100-HP source. After considering every origin, infection remains **false / false / true**. The first nearby ineligible slot blocks the valid pair. |
| T33 | Excluded source at x=0, corpse at x=30, living target at x=60, minimum distance 10: subsequent-link lookup selects the **corpse**. |
| T67 | Base time 100,000 ms, P1 at 100 HP: partner at 0 HP yields **95,000 ms**; partner at -80 HP yields **99,000 ms**. Overkill contributes an arbitrary four-second penalty. |
| T23 | P2 alone presses fire while both reload from 1 second over a 0.01-second step: timers become **0.99 / 0.94**. The rewrite already gives P2 Anxious Loader. Both portable input wrappers also read the current player's fire-pressed flag. |
| T44 | `perk_can_offer` rejects **Grim Deal, Fatal Lottery, and Random Weapon** for two players. Their flags are 0, 4, and 5; none has the co-op allow bit 2. |
| T26/T27 | Plague from 15 HP and a stationary Radioactive target seeded with exactly its next pulse's float32 damage both reach **0 HP, 0 XP, no ordinary death event**. Radioactive normally uses its own reward path; the defect is missing that reward at equality. |

## Corrections to the supplied catalog

- **T01/T02 are not entirely dormant.** HOLD_TIMER creatures skip the usual
  velocity update; close-contact movement can consume a previously stored
  impulse. The prior #818 investigation reproduced the diagonal drift.
- **T10 is not merely UI.** `shots_fired` is recorded and compared by replay
  validation; changing it requires coordinated Python/core/result expectations.
- **T13/T19/T65 are not automatically replay-neutral.** Sprite/effect state,
  allocation, lifetimes, and RNG can participate in snapshots or pool pressure.
  Classify the actual patch, not just its visible motivation.
- **T25 is not simply “self-match prevents all spread.”** The higher-indexed
  member of an isolated pair can infect the lower one. The real problem is
  stopping at the first nearby slot even when it cannot exchange infection.
- **T26/T27 are not duplicates of ledger #18.** That fix is restricted to
  `player_take_damage`; both creature DoT paths still use strict negative HP.
  The wider Radioactive reward redesign is a separate question.
- **T28's XP is already documented mechanics.** Energizer's reward surplus
  is not enough to establish an unwanted bug; missing kill accounting is a
  separate question.
- **T44's normal co-op exploits are unreachable.** Bypassing offer validation
  to call `perk_apply` does not prove an exploit in normal play.
- **T48's 75% refers to the forced branch on eligible kills**, not a measured
  75% reduction in all successful drops. The ordinary drop gate and suppression
  rules still apply.
- **T49 combines three different policies.** An expired NONE pickup is a
  clear defect; shared pickups and dead-player MediKit revival are documented
  co-op mechanics, with consequences beyond adding `break` or a health check.
- **T58 assumes intended constants and symmetry.** Saturated green is real,
  but `0.0001` is an inferred replacement. Equal Typ-o spawn heights are not
  inherently wrong; manual reload is unnecessary in its unlimited-ammo mode.
- **T68's `+pi/4` is not an independent rotation bug.** The quad path uses
  diagonal corner vectors. Its inability to preserve non-square aspect ratios
  is the separate defect; removing the offset alone breaks square rotation.

## Disposition of every catalog entry

“Adopt” means recommended for default mode, not yet implemented unless stated.
“Validate” means evidence or intended replacement is insufficient for inclusion.
“Preserve” means behavior may be odd but no default gameplay change is justified.
Source-only classifications below are not claims of native runtime reproduction.

| ID | Disposition | Reason / boundary |
| --- | --- | --- |
| T01 | Implemented (#49) | Impact-aligned death slide, #818; live HOLD_TIMER exception disproves “100% dead code.” |
| T02 | Implemented (#49) | Correct Y sine component; keep a regression for the already-live HOLD_TIMER path. |
| T03 | Preserve pending design | Corpse collision window is explicit; primary-hit fast-forward versus blocking needs a gameplay decision. |
| T04 | Preserve pending balance decision | #820 is confirmed, but fixing it substantially nerfs Gauss, Blade, and Fire Bullets. |
| T05 | Preserve / cleanup only | Discarded no-op is not a player-facing defect. |
| T06 | Adopt | Player-owned Splitter shards should respect friendly-fire policy; separate attribution from exclusion. |
| T07 | Adopt with T06 | Excluded first overlap should not conceal other valid targets. |
| T08 | Preserve pending timing design | Last damage tick can be an integration convention; quantify total damage before changing it. |
| T09 | Adopt death-state fix | Prevent duplicate death rewards; keep the documented 9.5 base damage unless separately rebalanced. |
| T10 | Adopt accounting fix | Count each converted projectile once, in Python and core; result/replay-visible. 1.9.8 recursion is a separate version. |
| T11 | Implemented (#46) | Duplicate ordinary death handling is confirmed, including four split children. |
| T12 | Prioritize trajectory comparison | Controlled Python probe confirms a cap-speed rocket can face a crossing target without turning its velocity. Retargeting also checks only active slots, so dying targets remain locked. Compare a normalized cap and living-target reacquisition before adoption. |
| T13 | Adopt separately | Correct cosine/cosine trail drift; verify sprite-state parity and whether rendered motion is improved. |
| T14 | Preserve pending balance decision | Timeout explosion strength and silence differ, but the intended timeout policy is not established. |
| T15 | Preserve | Short torch range may be intentional weapon differentiation. Do not infer a fivefold range buff from an unreachable phase. |
| T16 | Validate, limited reach | Check Bubblegun availability and target-slot reuse. Follow captured targets and prevent duplicate deaths only with a complete ownership/lifecycle design. |
| T17 | Preserve | Ignored movement/jitter parameters can be deliberate weapon behavior; removing draws changes replay state for no benefit. |
| T18 | Implemented for rules 2 | Six/five Fire Bullets with normal multi-pellet cooldowns (#832). Keep legacy counts/cadence for rules 1 and preserve_bugs; casing flags remain separate. |
| T19 | Validate / do not rotate wholesale | Effects may be lateral ejection rather than muzzle smoke; inspect the actual sprite and renderer. |
| T20 | Validate by perk | Ring conversion may be unwanted; Fire Cough already spawns a Fire Bullets projectile plus a smoke sprite, so its shot accounting is separate from converting plasma/ion rings. |
| T21 | Adopt movement cap | Relative backward Mean Minigun speed bypass is a clear control-mode inconsistency. Input-code truncation needs current seam reachability checks. |
| T22 | Implemented (#44) | Post-swap readiness fixes solo play. Independent cooldowns also handle granted co-op perks; normal co-op offers exclude Alternate Weapon. |
| T23 | Already addressed in current input handling | Python and both portable wrappers use each player's own fire-pressed flag; document original limitation rather than add another fix. |
| T24 | Split / preserve pending design | Death Clock part is ledger #27. Projectile dodge/armor, survival handout eligibility, and sounds require separate decisions, not blanket routing through player damage. |
| T25 | Adopt after interaction spec | Confirmed first-neighbor blocking; keep infection rate/budget bounded. |
| T26 | Implemented (#48) | Exact-zero Plague deaths receive normal rewards and stop live behavior that tick. |
| T27 | Implemented (#48) | Correct equality and death-frame fallthrough; retain base-only Radioactive rewards, no drops/splits, and the lizard exemption. |
| T28 | Preserve XP; validate kill count | Energizer's extra base XP is documented. Correct disappearance accounting without changing its economy. |
| T29 | Preserve | Small-creature contact self-destruction is an established branch, not proof of accidental missing XP. |
| T30 | Low priority / validate reachability | Asymmetric clamp is suspicious; ordinary eligible sizes may never reach either bound. |
| T31 | Preserve | Parent status inheritance and redundant RNG are not independently undesirable behavior. |
| T32 | Adopt lifecycle bookkeeping after repro | Centralize exactly-once kill accounting and spawner release across removal paths; avoid counting already-baked corpses twice. |
| T33 | Implemented (#47) | Both queries require living targets. This does not fix Seeker retention of an already-acquired dying target. |
| T34 | Validate separately | Formation fallback is preserved by source parity; changing it modifies authored quest enemy composition. |
| T35 | Validate separately | Root/last-child corruption is plausible; reproduce affected template and difficulty before changing quest layouts. |
| T36 | Validate reachability | Trace real callers of template 0x37 and establish intended projectile/cooldown. Do not invent missing values. |
| T37 | Preserve | Unused alternate cooldown configuration alone does not establish a wrong hardcoded attack rate. |
| T38 | Validate | Recycled timer state is real; measure gameplay impact and decide a deterministic initial phase. |
| T39 | Validate parity/run-down policy | Dormant-player targeting concerns the end-of-run interval; inspect current synthesized players and termination before changing it. |
| T40 | Adopt after focused co-op repro | Recompute target distance on redirection; localized one-frame co-op correctness candidate. |
| T41 | Preserve pending formation design | Cyclic linkage and transition to pursuit are not enough to infer an intended orbiting chain. |
| T42 | High-priority validation | Spawner-slot aliasing can alter spawn rates. Demonstrate peak simultaneous owners in stock/hardcore quests; overflow allocation needs a capacity/state-contract design. |
| T43 | Adopt | Positive-HP dying clear is inconsistent. Preserve no-XP semantics and handle a zero-delta perk command explicitly. |
| T44 | Reject normal co-op exploit claim | All three perks are excluded from two-player offers. |
| T45 | Preserve / dead-code cleanup only | Shareware fallthrough is outside the full-version gameplay target. |
| T46 | Preserve / dead-code cleanup only | Unreachable blocklist ID does not reveal which perk was meant. |
| T47 | Preserve | Fixed Sharpshooter spread can intentionally replace older cooling code. |
| T48 | Adopt | Forced forbidden weapon drops cancel ordinary bonus opportunities with My Favourite Weapon. |
| T49 | Split | Adopt expired-NONE early exit. Preserve shared-pickup/revival behavior until a coherent co-op policy is chosen. |
| T50 | Preserve pending API decision | Hardcoded durations are documented. Supporting carrier amount overrides is a feature/policy change, not necessarily a timing bug. |
| T51 | Validate quest rebalance | Missing increment overwrites the Fortress entry, but restoring a boss substantially changes quest difficulty. |
| T52 | Validate quest rebalance | Source timestamp is clear; moving the wave to 33.5 seconds is inferred intent. |
| T53 | Preserve | Spawn table entries need not be chronologically sorted; prove wrong runtime ordering before fixing. |
| T54 | Preserve pending quest design | A shorter/empty wave can be intentional pacing. |
| T55 | Reject missing-branch inference | Modulo four with an else naturally gives a 1:1:2 mix; it does not prove a fourth species was intended. |
| T56 | High-priority persistence follow-up | Python bounds tier-five counters, recovered game paths still index the legacy layout. Audit attempts and completions together; do not reproduce memory corruption merely for bug parity. |
| T57 | Adopt robust audio thresholds separately | Window skips are plausible; retain event-once semantics and RNG/audio separation. Post-clear death victory needs an explicit win-condition decision. |
| T58 | Preserve / presentation review | No established replacement for green timing or symmetric spawn positions. Current run initialization should be checked before claiming a first-shot weapon bug. |
| T59 | Validate | Reproduce repeat-tutorial state and carrier-pointer reuse in the actual client. Tutorial is outside verifier gameplay scope. |
| T60 | Adopt after draw capture | Out-of-loop player index is a strong renderer defect; check current game/port rendering and compare glare before restoring a 160px glow. |
| T61 | Split | Gauss transition alpha is a sensible render fix; shared impact glows may be an intentional art effect. |
| T62 | Adopt presentation fix | Slot-zero omission is clear. Changing arc radii needs an explicit decision to match damage rather than preserve visual reach. |
| T63 | Adopt after draw capture | Remove draw-order-dependent UV/rotation state; verify orbit math against the visible effect. |
| T64 | Split | Fix wrong dying sprite row and P2 hover eligibility after capture; discarded glow/rotation setup does not prove missing artwork. |
| T65 | Validate separately | Decal size jumps and stale templates deserve tests; state/pool effects can be replay-visible despite visual motivation. |
| T66 | Persistence/UI follow-up | Correct comparator and verify ranking/truncation with fixtures. File naming may require migration; do not silently swap existing score files. |
| T67 | Adopt co-op score clamp; separate UI fixes | Negative HP penalty confirmed. Name-caret truncation and music-track checks belong to independent UI/audio tests. |
| T68 | Split | Cursor AND/OR is a plausible UI fix; non-square rotation is an engine defect. Reject treating `+pi/4` as independently wrong; validate texture-cache behavior at the actual adapter. |

## Follow-up: C01 randomized perk intervals interfere across co-op players

This was missing from the supplied T01–T68 catalog. The original and pre-fix
rewrite give each player separate `fire_cough_timer` and `hot_tempered_timer`
accumulators, but compare them against global randomized thresholds. When
either player fires, that player subtracts the old interval from their timer
and re-rolls the threshold used by both players. These are neither independent
clocks nor a deliberate simultaneous team proc: one player's shot can postpone
or advance the other's next shot.

A controlled Python player-update probe reproduced the interference in both pre-fix
bug policies: start both timers at 1.35 seconds with the initial threshold
approximately 1.4, advance each by 0.1 seconds, and force the next interval to
2 seconds. Updating P1 first fires only P1, leaving timers approximately
`[0.05, 1.45]`. Reversing update order fires only P2 and produces
`[1.45, 0.05]`. Fire Cough emits one projectile, Hot Tempered one eight-shot
ring; independent thresholds would let both players fire in this setup.
This is a Python runtime reproduction with recovered-source confirmation,
not a separate original-executable probe.

Implemented independent per-player thresholds in default mode, using the same
initial delay and existing interval distributions (Fire Cough 2–5 seconds,
Hot Tempered 2–9). Do not add artificial desynchronization or force the players
to fire together. Retain the shared RNG stream and deterministic update order.
Man Bomb's threshold is also global, but stays at a fixed four seconds, so it
does not have this re-roll interference. Its separate timers can naturally
line up if both players remain still.

Evidence: `src/crimson/perks/state.py:8-18`,
`src/crimson/sim/state_types.py:77-80`, `src/crimson/gameplay.py:532-570`, and
`decomp/1.9/crimsonland/gameplay/player_update_heading.cpp:373-478`.
Implemented as ledger #43; see [#821](https://github.com/banteg/crimson/issues/821).

## Follow-up review: recommendations beyond the implemented bundle

The supplied GPT Pro review used the base commit, before this working-tree
implementation. Its death-orientation, Shock Chain, rocket duplicate-death,
DoT-boundary, swap and scoring recommendations are already covered above.
The following are recommendations, not additional implemented fixes:

- **Promote T06/T07 (Splitter) for the next extension.** Child shards still use
  the struck creature as their owner, which permits player damage with friendly
  fire off. Separate allegiance/player ownership from collision exclusion, and
  continue searching past an excluded overlap. Preserve the exclusion to avoid
  immediately re-hitting the parent; define exclusion lifetime and slot reuse.
- **Promote T48 (Pistol/My Favourite Weapon).** The forced weapon-drop route
  still rolls, allocates, clears the prohibited weapon and returns before the
  ordinary bonus path. Bypass that route when weapons are prohibited; retain
  the normal bonus gates, rather than guaranteeing a replacement bonus.
- **Promote a bounded T25 (Plague transmission) specification.** Find one
  eligible transfer per call while retaining radius, HP threshold, cadence and
  budget. Skipping only self is insufficient. Removing first-ineligible-neighbor
  blocking does not make an in-place propagation algorithm entirely independent
  of iteration order; do not accidentally turn it into all-neighbor spread.
- **Prioritize T12 (Seeker) trajectory validation.** In the current default
  Python movement function, a rocket at `(100, 100)` with velocity `(350, 0)`
  and a target at `(100, 1000)` retains velocity `(350, 0)` after a 1/60-second
  tick while its facing changes. With that target at -1 HP and death timer 10,
  it also retains target slot zero despite a living alternative. The new #47
  acquisition predicate does not repair the active-only retention check in
  `_move_rocket`. These are controlled Python probes, not fresh executions of
  the original binary. Compare crossing-target and overshoot trajectories before
  adopting acceleration followed by magnitude limiting at 350.

**Adopted T18 extension:** use six Gauss Shotgun and five Multi-Plasma Fire
Bullets under rules 2 default, consistent with other multi-pellet conversions.
Retain each weapon's normal cooldown (1.05 seconds and approximately 0.6208117
seconds before perks). This is an explicit consistency/balance decision,
tracked in [#832](https://github.com/banteg/crimson/issues/832), implemented in the final stack layer. Rules 1 and `preserve_bugs` retain old counts
and cadence. Normal unconverted firing remains unchanged.

Gauss currently uses the single-pellet Fire Bullets cooldown of 0.14 seconds.
Ignoring discrete ticks and perks, nominal throughput changes from about 7.14
to 5.71 projectiles/second, with different burst coverage. Multi-Plasma normally
mixes three Plasma Rifle and two weaker Plasma Minigun bolts; five converted
Fire Bullets are uniform. Fire Bullets already suppresses ordinary ammo
consumption, so the earlier ammo-economy concern was overstated. Keep that
suppression. Evidence: `weapon_runtime/fire.py` cooldown selection, conversion,
ammo gate and weapon dispatch, and `weapons.py` metadata.

A separate death-lifecycle pass remains worthwhile for Shrinkifier, Breathing
Room and immediate removals. Preserve negative overkill HP and ordinary
collapse-time kill counting; repair repeated rewards and missing counts per
cause. Bubblegun target identity needs a generation check, but its ID 42 is
outside the ordinary random-drop range 1–33, so it is not an equally urgent
normal-play fix. Spawner-slot exhaustion is a confirmed allocator fallback,
but its priority still needs a reachable workload and an explicit capacity
policy. Shared pickups and dead-player MediKit revival remain design decisions.

For presentation, slot-zero Ion arcs and scale-consistent terrain decals are
promising small follow-ups. Verify both normal and overflow decal paths and
actual captures; particle-age/expiry changes are a separate simulation change.

## Rules-version and release boundary

Use **one rules bump, 1 → 2**, for this batch. The branch changes both
`src/crimson/game_version.py` and `service/src/replay.ts`; the game reads
the Python constant at build time, and the service checks rules before core
verification. Further fixes in this unreleased batch do
not need independent version increments. Format version 34 is unchanged: this
is gameplay compatibility, not an encoding change.

The compatibility stack layer selects explicit rules-1 and rules-2 profiles. `--preserve-bugs` chooses
original behavior, not the previous default rules, and is not a substitute for
rules-version compatibility. Do not relabel old recorded results/checkpoints as
rules 2. Keep historical fixtures for codec and original-reference work, and
record new default-policy fixtures for changed behavior.

The selected release plan is to retain rules-1 playback and verification while
making rules 2 the default for new runs. Keep existing leaderboard entries,
IDs, scores and signed replay bytes. Proposed presentation: combined boards
with rules labels and an optional filter. Simulation selects the recorded profile, including the historical co-op
manual-reload exception.
See the [implementation plan](replay-rules-compatibility.md) and
[#833](https://github.com/banteg/crimson/issues/833). Client, service and verifier
must support this before release. No deployment or migration has been performed.

## Validation of the implemented changes

- The 1,688-test Python suite passed; five additional splitter/spawner slide
  regressions also passed. The bundle regression file contains 48 cases covering
  both policies. Original-executable impact witnesses run under `preserve_bugs`.
- Native/WASM agree on 163 generated scenarios, including reset checks. Python
  and the native core agree on 169 streams (163 scenarios plus six recordings),
  including recorded results and fresh per-tick checkpoints. Game/verifier
  comparison also passes all 169 streams.
- The service passes 119 unit tests and 73 API/verifier/co-op worker tests;
  TypeScript checks and the web build pass. Old and future rules are rejected.
- Replay reading passes nine playable cases, two seated cases and 22 malformed
  cases. Watch passes eight runs; seek passes 158 targets, including co-op perk
  timer restoration. Practice passes 15 anchors and 1,920 alternate-input ticks.
- Six current-rule fixtures were regenerated from bot inputs; a separate run
  reproduces their results and checkpoint data. Historical rules-1 fixtures
  remain untouched and now play through the compatibility layer.

The complete co-op suite passes all 22 stream variants and every coverage
assertion, including forced rollbacks, delayed/lost packets, the state audit,
connection lifecycle checks, and six-/seven-choice menus. It exercises 44 held
overflow-decal bakes and 732 rollbacks into open menus. Its raw-state diagnostic normalizes
consumed decal-queue entries: immediate and held overflow bakes leave different
unread bytes there. Live queued decals remain compared, and separate bake and
terrain digests verify the rendered output. This is not a new interactive visual
assessment of every lethal source. No release or deployment was performed.
