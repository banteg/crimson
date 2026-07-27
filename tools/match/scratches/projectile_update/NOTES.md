# `projectile_update`

The current MSVC 6.5 `/O2 /GB` candidate recovers all four native simulation
phases at `0x00420b90`. The primary pool covers active/lifetime handling,
lingering ion and Gauss damage, world-bounds expiry, travel-budget microsteps,
creature and player collision, perk hooks, projectile-specific hit behavior,
penetration damage, decals, freeze effects, and impact audio. The secondary
pool covers rocket acceleration, seeker steering, smoke trails, collision
damage, detonation AoE, and type-specific debris and freeze bursts. The
trailing phases cover sprite-effect integration plus particle movement,
expiry, style-specific steering, collision attachment or deflection, fire
damage, tint decay, sprite/decal emission, and creature displacement.

It produces 2,145 instructions against 2,203 native instructions, scores
48.11%, and audits `351/0/25` references. The candidate's natural local frame
is `0xa8`, while the native function uses `0xf4`.

## Binary Ninja evidence

The primary 96-entry loop advances a register cursor at the native
`sizeof(projectile_t) == 0x34` stride. Binary Ninja had inferred that cursor as
`char *`, leaving every access as a raw byte offset even though the global
pool already had the recovered type. Assigning the local
`projectile_t *projectile` type recovers `active`, position, velocity/lifetime,
type, owner, radius, and damage fields throughout that phase without changing
the source or matcher result. The later secondary and particle cursors are
intentionally anchored at `vel_y`, not at their containing records, so their
negative indices remain honest field-cursor artifacts rather than being
mis-typed as base pointers.

The small movement helper at `0x0041e400` reads and writes two adjacent floats,
then clears `eax`. Its recovered contract is therefore
`int vec2_add_inplace(int, vec2f_t *, const vec2f_t *)`, not the previous three
raw `float *` values and not Binary Ninja's former `void` return. The projectile
impact call now passes its named `impulse_pos` and zero vectors directly; this
preserves the exact helper and the whole projectile candidate.

Live disassembly confirms that the initial movement budget is
`(int)travel_budget`, doubled through an x87 integer-to-float round trip when
Barrel Greaser is active for a player-owned projectile. Each microstep adds
`cos/sin(angle - pi/2) * frame_dt * 20 * speed_scale * 3`, flushes the
accumulator at length 4 or near the loop tail, and advances the logical step by
three.

The microstep accumulator is now a `vec2f_t delta` in the matching source, and
the shared exact `vec2_add` boundary takes vector pointers. All ten raw
`delta[0]`/`delta[1]` accesses are replaced by `x`/`y`, including Pulse Gun
knockback and the reset after each collision batch. Binary Ninja independently
recovers the same stack slot as `vec2f_t delta`. The candidate remains
2,137/2,203 instructions at 46.91% with the same 336 aligned references.

Native constants read directly from the image recover the lingering cases:

- Ion Rifle: `frame_dt * 100`, radius `ion_scale * 88`
- Ion Minigun: `frame_dt * 40`, radius `ion_scale * 60`
- Ion Cannon: lifetime `frame_dt * 0.7`, damage `frame_dt * 300`, radius
  `ion_scale * 128`
- Gauss Gun: lifetime `frame_dt * 0.1`

The three ion damage cases are separately spelled source calls that VC6
naturally tail-merges. Native compares types `0x15`, `0x16`, and `0x17` at
`0x00420c16..0x00420c23`; each case stages its own damage and radius, then
converges on the sole `creatures_apply_radius_damage` call at `0x00420cc9`.
Writing one call after shared source locals leaves extra stores, while keeping
Ion Rifle, Ion Minigun, and Ion Cannon calls in their respective branches
reproduces the compare ladder, early argument pushes, and one-call result
without a source-level jump. This raises the aggregate candidate from 45.28%
to 45.40% and aligns 307 references.

The native damage impulse deliberately writes both vector components from the
same cosine term. The source retains that oddity because the disassembly and
the existing runtime parity implementation independently agree on it.
The local is now represented as a canonical `vec2f_t` and passed directly,
removing two array casts with identical codegen.

The primary penetration damage calculation is split across the weapon-specific
impact switch. Native keeps the clamped travel distance on x87, calculates and
stores `(100 / distance) * weapon.damage_scale * 30 + 10` immediately before
the switch, then multiplies that stored value by `0.95` immediately after the
switch. The recovered source now preserves that lifetime and reads the weapon
table directly instead of introducing a `damage_scale` local.

Native trig products consistently become single-precision at the trig result:
the projectile microstep uses float `cos`/`sin` values with `frame_dt` and
`20`, the primary impact vectors use float trig values with their randomized
speed, seeker acceleration uses float trig values with `frame_dt` and `800`,
and particle steering uses float trig values with `82` or `62`. Placing the
cast around each complete expression had promoted those constants to doubles.
The native smoke trail also calculates one cosine and deliberately uses it for
both velocity axes. Restoring these forms, plus the native float `hit_angle`
used by particle reflection, raises the aggregate candidate from 45.40% to
46.75%, reduces it from 2,136 to 2,131 instructions, and aligns 333 references
instead of 307 without changing the natural `0x98` frame.

The primary impact blood branch keeps the perk-active eight-splatter path as
the native fallthrough. The perk-inactive arm branches to the two-splatter
path, which is additionally gated by the freeze timer. This condition ordering
is semantically equivalent to checking the inactive arm first, but reproduces
the native block layout without a source-level jump.

Four weapon-specific primary-hit branches are now recovered in the Zig runtime.
Splitter type `0x1d` branches at `0x00420ed4`, emits its burst at `0x00420ee1`,
then calls `projectile_spawn` at `0x00420efa` and `0x00420f13` with the parent
heading minus/plus `1.0471976`, the same projectile type, and the hit creature
as owner before entering the shared hit presentation. Plasma Cannon type
`0x1c` branches at `0x00421367`, computes `creature.size * 0.5 + 1`, raises the
bonus-spawn guard, and loops 12 times over `i * 0.5235988`; each iteration calls
`projectile_spawn` at `0x004213e3` for local-player-owned Plasma Rifle type 9,
then the branch unconditionally clears the guard rather than restoring its
incoming value. Both runtimes preserve that literal guard transition.

Shrinkifier type `0x18` starts at `0x0042144b`: after the impact effect it
multiplies creature size by `0.65`, stores projectile lifetime `0.25`, and for
size below `16` calls `creature_handle_death(hit_id, true)` at `0x00421482`.
Plague Spreader type `0x29` branches at `0x004214cd` and sets the hit creature's
infection byte at `0x004214d2` before shared damage resolution. Focused runtime
tests cover all four branches, including Splitter ownership/headings, the
12-projectile Plasma ring, Shrinkifier's keep-corpse death path, and infection
ordering.

The chained Ion Rifle branch likewise writes the bonus-spawn guard to one at
`0x004212b1`, spawns the next segment at `0x004212ff`, and writes zero at
`0x00421304`. It does not restore the incoming guard. Both ports preserve that
literal continuation transition, and their regressions start with the guard
set so a save/restore implementation cannot pass accidentally.

Live callsite inspection also establishes that all six perk queries use the
singleton `perk_count_get` helper, which returns
`player_state_table[0].perk_counts[perk_id]`: Ion Gun Master at `0x00420bb5`,
Barrel Greaser at `0x00420d97`, Poison Bullets at `0x00420e73`, and Bloody
Mess / Quick Learner at `0x00420fbf`, `0x004210a7`, and `0x0042175a`. The last
query's return value is deliberately unused by the native Gauss / Fire Bullets
effect branch. Both ports now use player slot zero for the observable gates in
bug-compatible mode. Outside it, Ion Gun Master, Barrel Greaser, and Poison
Bullets retain their any-player behavior, while Zig retains owner-based Bloody
Mess presentation; Python presentation was already player-zero.

The secondary detonation path reuses `vel_x` as expansion time and `vel_y` as
scale, applies `frame_dt * scale * 700` damage inside `scale * time * 80`, and
keeps processing its TTL check after a hit. The latter can overwrite a freshly
selected type-specific detonation scale with `0.5`; the recovered source keeps
that observable ordering.

The direct secondary-hit sequence at `0x00421e70..0x00422381` preserves the
incoming rocket type in a local before changing the pool entry to detonation.
Its impact-audio branch (`0x00422079..0x004220b6`) precedes the damage call at
`0x004220eb`, so the first-hit playlist draw occurs before any lethal creature
death draws. The four pre-hit Freeze shards all use caller-static `0x00421eb3`;
the later eight-shard burst is type-specific, and Rocket Minigun emits it from
the hit creature position while Rocket and Seeker Rocket use the projectile
position. The exploding-secondary kill branch also emits its two random decals
even while Freeze is active, before calling the secondary death follow-up.
Zig now preserves this ordering, source local, caller provenance, and position
choice; focused trace tests guard the shared RNG stream.

The non-Freeze direct-hit decal sequence is three separately materialized
points rather than a source loop. Native disassembly calls `rand` at
`0x00421ee6`, `0x00421f05`, `0x00421f42`, `0x00421f61`, `0x00421fa7`, and
`0x00421fc6`, with queue calls at `0x00421f3d`, `0x00421fa2`, and
`0x00422007`. It stores the points in three distinct stack regions around
`[esp+0x74]`, `[esp+0x88]`, and `[esp+0x9c]`. Expressing those three values
independently restores the native whole-function call totals of 42 `rand`
calls and 16 `fx_queue_add_random` calls. The candidate grows from 2,101 to
2,143 instructions, improves from 44.05% to 45.28%, and aligns 305 references
instead of 301; its natural frame grows from `0x90` to `0x98`. The remaining
reference-region differences are ordinary sequence-alignment fallout, not
forced or unresolved references.

Each direct-hit point also has two native source lifetimes. At
`0x00421ef6..0x00422007`, VC6 first converts both random offsets, then adds the
hit creature position into a distinct destination vector before each queue
call. Preserving those offset and destination objects for all three points
grows the candidate from 2,131 to 2,137 instructions and its frame from `0x98`
to `0xa4`, raises the score from 46.75% to 46.91%, and improves the reference
audit from `333/0/30` to `336/0/29`. Applying the same split to the later polar
decal loops or the three scaled primary-impact points made the measured match
worse, so those source expressions remain unsplit.

The live particle tail confirms three deliberately duplicated jitter branches:
style zero uses a `1.96` turn factor and speed `82`, style eight uses `1.1` and
speed `62`, and the remaining styles use `1.1` and speed `82`. A particle hit
uses radius `intensity * 8`, deflects by `1.2566371`, scales the reflected speed
by `(rand() % 10) * 0.1`, and applies `intensity * 10` damage. Creature tint is
only darkened when the RGB sum exceeds `1.6`, using
`1 - intensity * 0.01`, followed by per-channel clamping.

The tint sum is evaluated in native PC=24 order as `(g + b) + r`; the fade
scales RGB only, while the subsequent clamp covers all four channels. After
the sprite/decal side effects, native also advances the hit creature by the
reflected particle velocity times `frame_dt`. Python now preserves the exact
PC=24 arithmetic without fading alpha, and Zig now models both the tint update
and the gameplay displacement instead of stopping after damage.

Bubblegun attachment copies the hit position once, zeros the particle velocity,
and retains the target id, but native does not make the attached particle follow
later creature movement. On expiry, an attached particle checks only the target's
active byte: it draws `sfx_bank_a[rand() % 3]` at caller-static `0x00422723`,
plays it at the creature position, then calls `creature_handle_death(target,
false)`. The target id remains stored in the now-inactive particle. Both ports
now preserve that order and stale-position/target state; Python no longer adds
an HP guard that suppressed native active-corpse death re-entry.
Both that audio call and the Rocket Minigun freeze-shard burst now take
`creature_t::position` directly instead of casting from `pos_x`.

## Remaining work

The native behavior is substantially represented, but whole-function MSVC
scheduling still differs. In particular, the native `0xf4` frame reuses many
long-lived vector temporaries across projectile and particle branches, whereas
the recovered structured source naturally compiles to `0xa8`. Further work
should improve original declaration/lifetime shape only when supported by
control-flow evidence. No dummy locals, volatile expressions, forced
references, inline assembly, or layout-only gotos are used to imitate the
native frame.

The primary projectile cursor is now one `vec2f_t *` from movement through
radius queries, hit effects, child spawns, and panned audio; the parallel raw
`float *pos` alias is gone. Sprite and radius-query boundaries also receive
typed stack or embedded positions. Binary Ninja independently renders the
corresponding calls as `&projectile->pos_x` vectors, and the saved creature
cursor is now a `vec2f_t *`. The change preserves 46.9124%, 2,137/2,203
instructions, and the `336/0/29` audit.

## Projectile-family aggregate recovery

The canonical source layout now overlays vectors on the mixed projectile
storage without discarding its type-bearing tail blocks: primary and secondary
positions, primary origin and velocity, secondary velocity, and particle
position/velocity are all named aggregates. `projectile_update` consequently
removes 17 first-float casts, and render code addresses the named position,
origin, and velocity views rather than `pos_x`, `origin_x`, or `vel_x`.
Sprite effects likewise expose RGBA color, position, and velocity aggregates.
The update remains 46.9124% at 2,137/2,203 instructions with `336/0/29`
references; projectile rendering remains 43.04%.

Binary Ninja keeps the existing named mixed projectile blocks because replacing
them with anonymous union overlays makes its HLIL regress to `__offset(...)`.
Its particle and sprite-effect records safely use direct named aggregates
instead, also correcting `particle_t::style_id` and
`sprite_effect_t::active` from stale 32-bit interpretations to bytes.

The projectile weapon-class gate now reads the canonical native weapon row as
`weapon_ammo_class[type_id].ammo_class`. This removes the decompiler-derived
31-dword stride without changing code generation: the candidate remains
2,137/2,203 instructions at 46.9124% with `336/0/29` references.

## Binary Ninja control-flow recovery

The saved database had stopped analysis at the default time limit, leaving this
2,203-instruction function without LLIL, MLIL, or HLIL. Its name-map row now
sets the narrow `never_skip` analysis policy; a forced reanalysis completes in
about four seconds and restores the full primary-projectile, secondary-
projectile, sprite-effect, and particle control flow.

The recovered HLIL confirms one owning `projectile_t *projectile` cursor. The
secondary-projectile walk is genuinely anchored at `vel_y`, and the creature
and particle walks are genuinely anchored at `pos_y` and `vel_y`; the importer
therefore gives those interior cursors descriptive names without pretending
that their pointer values are owning-record bases. The sprite-effect cursor is
left automatic because its register is reused for unrelated return values later
in the function. This presentation-only recovery preserves 46.91%,
2,137/2,203 instructions, and `336/0/29` references.

The explosion-radius creature walk now names
`creature_t::position.x/y` from its owning record pointer. The surrounding
primary and secondary projectile paths retain their nested views because their
native induction cursors genuinely begin inside those records. This targeted
type recovery is byte-neutral at 46.91%, 2,137/2,203 instructions, and
`336/0/29` references.

The plasma projectile effect now writes its size through
`effect_template_t::half_extent`, completing the template aggregate boundary
already used for velocity and color. This is byte-neutral at the same 46.91%,
2,137/2,203 instructions, and `336/0/29` references.

Every owning-record coordinate in the update now follows the same rule.
Primary and secondary projectiles, hit creatures, sprite effects, and
particles use their canonical `position` and `velocity` components directly;
only native induction cursors that genuinely begin inside a projectile record
retain the nested compatibility views. The 39-component rewrite is exactly
byte-neutral at 46.91%, 2,137/2,203 instructions, and `336/0/29` references.

## Reference residual re-audit

A fresh corpus audit keeps the candidate at 46.91%, 2,137/2,203 instructions,
and `336/0/29` references before and after classification. All 29 entries are
aligned mismatches; there are no unresolved references. Several entries
directly prove SequenceMatcher drift rather than data-layout debt: a native
`vec2_add` call is paired with candidate `creature_find_in_radius`, and a
native `effect_spawn_ion_hit_sparks` call is paired with candidate
`sfx_play_panned`. The global entries similarly pair different phases or
fields of already typed pools.

Live Binary Ninja at `0x00421ca0` confirms the native creature position reads
at `creature_pool+0x14` and `+0x18`, followed by an address calculation for
that same position. BN reports the complete `creature_pool` as 384 typed
`0x98`-byte records and the projectile, secondary-projectile, particle, sprite,
and effect-template objects at their existing mapped boundaries. No offset or
alias correction is supported. The residual is therefore compiler scheduling
only, and `RESIDUAL=compiler` preserves all 29 honest mismatches.

## Branch-local penetration impulse lifetimes

Live Binary Ninja HLIL separates the two mutually exclusive penetration-damage
vectors: the exhausted-pool arm materializes one at `0x0042153c`, while the
surviving-pool arm materializes another at `0x00421573`. Keeping one source
aggregate above the damage-pool branch hid that original lifetime distinction.
Declaring the identical impulse in each real call arm raises the candidate from
46.9124% to 47.2024%, from 2,137 to 2,140 instructions, and from `336/0/29` to
`340/0/29` references. Its natural frame grows from `0xa4` to `0xa8`.

The later Rocket, Seeker Rocket, and Rocket Minigun decal loops also appear in
three different native stack slots. Hoisting three named aggregates across
those mutually exclusive arms was tested, but VC6 emitted exactly the same
candidate and metrics. The simpler scoped declarations remain.

## Compiler-residual cursor refinement

The first current mismatch is still the honest `0xa8` candidate frame versus
the native `0xf4` frame. Past the prologue, native loads the primary entry's
active byte through the scaled pool index and only then materializes the typed
projectile cursor with `lea`. Binding the source pointer inside that real
activity gate reproduces the same order. It raises the candidate from 47.20%
to 47.97%, reduces the rounded fuzzy gap from 4,440 to 4,375 bytes, changes the
instruction count from 2,140 to 2,141, and improves references from `340/0/29`
to `351/0/25`.

A named copy of the active byte and moving the tick increment ahead of the ion
scale declaration both compile byte-identically, so neither cosmetic spelling
is retained. A 20-profile matrix covered MSVC 6.0, 6.5, 6.5pp, 6.6, and 7.0
with `/GB`, `/G5`, `/G6`, and `/Oy-`; extended VC6.5 probes also covered
`/Ob0`, `/Ob2`, `/Oi-`, `/Og-`, `/Os`, `/O1`, and `/GX`. Stock MSVC 6.5
`/O2 /GB` remains tied for best with 6.0, 6.6, and `/G5`; no override is
supported.

The current proof point is therefore 2,145/2,203 instructions at 48.11%, with
`351/0/25` references and no unresolved static reference. The remaining
first-region difference is stack-slot displacement from the wider native
temporary frame, not a missing operation.

## `vec2_add` caller-mode contract

A fresh region pass selected the accumulator-flush span at
`0x00420de3..0x00420e54`. The native call at `0x00420e41` pushes a third
`0.0f` argument before the delta and destination pointers, while the former
two-argument declaration omitted that real caller value. A live callsite audit
of `vec2_add` at `0x0041e270` establishes the complete contract: the primary
projectile call passes `0.0f`, the secondary movement call at `0x00421bd1`
passes `4.0f`, and the particle calls at `0x00422586` and `0x0042265b` both
pass `3.0f`. The helper body does not consume the float, so its standalone
machine code cannot distinguish a two-argument declaration from this recovered
three-argument caller contract.

The tracked schema-1 mutation plan first tested all four sites independently.
Restoring a default-zero third argument was the only compiling single and
improved the weighted match from `4034/8409` to `4042/8409` bytes
(`47.97%` to `48.07%`). That justified the complete four-depth interaction
sweep. The observed `0/4/3/3` combination ties the best result at `4046/8409`
bytes (`48.11%`); it is retained instead of the shorter tied variant because
the native particle callsites directly prove both `3.0f` values. The final
candidate grows from 2,141 to 2,145 instructions, reduces the rounded fuzzy
gap from 4,375 to 4,363 bytes, and preserves the `351/0/25` reference audit.
Both the single-site and exhaustive 15-variant interaction sweeps are recorded
in `experiments.jsonl`.

## Native movement-local lifetime sweep

Live Binary Ninja maps the early movement locals to five distinct native frame
slots: `step_y` at `-0xf4`, `step_count` at `-0xdc`, `step_x` at `-0xd0`,
`delta` at `-0xcc`, and `step` at `-0xc4`. Their values are still computed at
the same control-flow points, but declaring the aggregates and scalars at
function scope exposes the longer native lexical lifetimes to VC6.5. All seven
tested declaration orders compile byte-identically once paired with the real
use-site assignments. The retained source order raises the weighted match from
`4045.91/8409` to `4200.63/8409` bytes (`48.1141%` to `49.9540%`), reduces
the fuzzy gap by `154.72` bytes, and grows the natural frame from `0xa8` to
`0xac` toward the native `0xf4`. The instruction count remains
2,145/2,203; references move from `351/0/25` to `357/0/27`. The complete
15-variant sweep is recorded with spec SHA
`37ebe5035facae9888454c6d14becb46fe21c675bb0a9b6d3107ec75ebf1fa43`.

Three bounded follow-up matrices reject broader lifetime hoisting:

- Hoisting the six direct secondary-hit decal vectors to function scope loses
  `185.66` weighted bytes in every activated ordering. The seven-variant
  sweep is recorded with spec SHA
  `8390093cc213a658c3f7526c8658b8daa6dae5343689f2be129a32c0b30240b9`.
- At the secondary explosion block `0x00421a52..0x00421a9e`, hoisting only
  the scalar extent is byte-neutral, while activating the four-float color
  loses `181.80` weighted bytes. The complete 19-variant sweep is recorded
  with spec SHA
  `2801d46a17e72cadaacd081794a74a53c978f3564a682227cfdee39ff895393d`.
- Native `0x004217df..0x004218d9` uses distinct physical slots for the
  primary impact impulse, zero, freeze-shard, and decal vectors. Moving any
  subset to the surrounding Gauss/Fire loop scope nevertheless compiles
  byte-identically for all eight valid interactions. The full 15-variant
  matrix is recorded with spec SHA
  `f1b82ba3ca88f57380aa3eb99cb517c14e3d3bf4997e9d6a5714e4f50be801e8`.

Those negative results keep the simpler branch-local declarations and narrow
the remaining `0x48` frame deficit to other native temporary groups rather
than these later effect vectors.

Two additional native-shape probes also reject superficially closer spellings:

- At `0x00420f3f..0x00420fa9`, native writes the effect template metadata and
  RGBA components directly. Replacing the semantic color aggregate with those
  direct component stores nevertheless removes eight candidate instructions
  and loses up to 3.88 weighted bytes; a component-local-then-copy form is
  byte-neutral. The six-variant sweep is recorded with spec SHA
  `743a41ebe99f52f5599143d01b692a2e1cd4ace0ede5e3fd0a7b074e63153073`.
- The Bloody Mess double impact at `0x004210e2..0x00421183` uses distinct
  native vector slots, but splitting the reused source aggregate loses 119.91
  weighted bytes and activating function-scope copies loses 205.00. Mere
  function-scope declarations are byte-neutral, so the simpler reused
  aggregate remains. The complete 17-variant interaction sweep is recorded
  with spec SHA
  `f8836b8b398ef179e60e4a0b86463a1a06d05447739e4bc42bf7e31ee9d57fa5`.

## Native particle hit-angle geometry

A fresh live Binary Ninja export from target
`3023:2:9499448411019345244` has HLIL SHA-256
`3e29b5b5217f5cf7494380497272c903c80eb07d2a6f3e21eef5d13fde0d7204`
and disassembly SHA-256
`417f4c7a6dfe6f64d9e6a6da1c911c07c17e5e575a59f8247db83a22592c6d55`.
At `0x00422936..0x00422981`, native does not collapse the particle collision
heading into two `atan2` arguments. It first materializes
`frame_dt * velocity` in `pos_2`, subtracts that from the particle position
into `pos_3`, and then subtracts the hit creature position into `impulse`
before calling `atan2`.

`particle-hit-geometry-mutations.json` records all four bounded spellings with
spec SHA
`27e9b694764f47d54c120579c71911e443ca407a6234034b28b0b2d97497677f`.
The native-complete three-vector form is the unique best result: it adds five
candidate instructions, raises the weighted match from
`4200.6320/8409` to `4207.3977/8409` bytes
(`49.9540%` to `50.0345%`), and reduces the fuzzy gap by `6.7656` bytes.
The independent recorded probe reproduces the same source SHA-256
`53f5991434dba671cc095787f498ae7ff2ee1f7e338cbc02dd9a05b2b672d09d`.
References move from `357/0/27` to `356/0/27`; there are still no unresolved
references.

Moving the three recovered vectors to function scope is byte-identical in all
three tested declaration orders, so the simpler collision-local declarations
remain. The complete lifetime sweep has spec SHA
`248a10be4a412739967d4f92ee64c90e3505be27c87ce7624aca2d131b02b312`.
A separate four-form test of staging the final hit-creature displacement
regresses by at least `148.68` weighted bytes, despite the native tail's
temporary stores, so the direct component update remains; that sweep has spec
SHA
`70cac96726095e03e48b873893eae5ced8dd5a6ae69ae503c9bffc5bb9a994bb`.

Other live-slot hypotheses were also fully bounded and rejected. Hoisting the
secondary trail vectors is byte-neutral
(`69860cf13e02b46f5be6a904ddda834b54ad988946c9643ef46ea0a3e79ba0d7`).
Cross-phase reuse of native `var_a0` loses at least `123.78` weighted bytes
(`6602301ee6b8351a47771344b0908d2466e291c2cc8d96b792708da701532ba3`).
Separating the exploding-secondary normalized direction from its scaled
damage impulse also regresses as direct locals, function-scope locals, and a
returned-value helper, recorded under spec SHAs
`43c96baa64ab1a487e2c767a07f7cb645585ec60d8ed05a39d2d05f8cc876ccb`,
`671a8c10d1dab9b7017ea2b8daadb4bea54bbbde1b04efdd1ff742f51be5583a`,
and
`7aeb552b56083433b31e489d7a7be37c119dfb3c03e2d4b5a90dd880fc2eadd0`.
No rejected source spelling is retained.

## Particle-hit tint normalization follow-up

The next coherent reference cluster is the particle-hit tint normalization at
`0x00422a54-0x00422b8d`. Live Binary Ninja shows the native x87 stream sums
`tint_g + tint_b + tint_r`, scales `tint_r`, `tint_g`, and `tint_b` in that
order, then clamps `tint_r`, `tint_g`, `tint_b`, and `tint_a` to `[0, 1]`.
The current source has the same runtime semantics and channel order, but VC6.5
canonicalizes its sum to a different operand schedule and carries two scaled
results through stack temporaries where the native stream reloads the fields.

Three complete bounded sweeps reject natural source-shape corrections:

- All five alternative sum permutations are byte-identical to the baseline.
  The complete sweep has spec SHA
  `62d2cb9ddb198f5b498819e6f55c6aea5cc1e9390f98c6a84de68ae7ff2c212a`.
- Explicit `channel * scale` and `scale * channel` assignments are both
  byte-identical. Their spec SHA is
  `0b855d57777721cc14ed12409b98e84c2b0f701f0d2ae879cb3065bdade025e1`.
- Replacing the four direct clamps with a native-order inline value helper
  loses 87.837 fuzzy-weighted bytes, grows the candidate by three
  instructions, and drops eight correctly aligned references. Although three
  mismatch labels disappear as a side effect of the changed alignment, that
  is not a real gain. The complete helper interaction sweep has spec SHA
  `9a6a3fc19bcf3c89054bf7fb3b0e678c1e92d7762aaec0e7e6036d25e4c69abf`.

No tint source variant is retained. The update candidate remains source SHA
`53f5991434dba671cc095787f498ae7ff2ee1f7e338cbc02dd9a05b2b672d09d`
at 50.0344590%, 2,150/2,203 instructions, a 4,201.602-byte fuzzy gap, and
`356/0/27` references.

## Sprite and particle movement lifetime refinement

The next highest uncovered mismatch region is native
`0x0042241c-0x00422782`: 870 target bytes with 243.181 fuzzy-weighted bytes
matched and a 626.819-byte local gap at the starting checkpoint. Live
disassembly from explicit target `crimsonland.exe.bndb` shows two recoverable
source lifetimes inside that larger compiler-residual region. A fresh
MSVC 6.5 profile check also confirms `/O2 /GB` and `/O2 /G5` remain
byte-identical, so the difference is not a processor-flag artifact.

At `0x00422476-0x0042249a`, native loads `frame_dt` once, duplicates it on
x87, materializes the x displacement, and carries the y displacement until
both sprite-position updates. Of five complete source variants, a staged
`frame_dt` feeding a `vec2f_t` initializer is uniquely best. It raises the
whole-function weighted score from 4,207.3977 to 4,213.1890 bytes, adds two
candidate instructions, and changes references from `356/0/27` to
`357/0/24`. The independent probe reproduces source SHA
`f2ca8821a9cae6bb5110c52bf536c19426d3586b53dcd17d4c15fdca76e755f5`;
the sweep spec SHA is
`06b9bdb85bb180875bef9f95d9d8b1fe3ab323a6b3186d6b57e08463ffcc73e0`.

Native begins the intensity comparisons at `0x0042253a` and `0x004225f5`
before scheduling the shared x displacement in both particle movement arms.
Putting the identical `move_x` declaration in each real low/high branch lets
VC6 recover that ordering. The complete two-site interaction sweep raises the
intermediate score by another 5.7993 weighted bytes, restores the candidate to
2,150 instructions, and adds one aligned reference without adding a mismatch.
The independent probe reproduces final source SHA
`6bad34cc75c3c2bee965e2eae98958fac4a51cd219d03659d17f8c1deab4c115`;
the sweep spec SHA is
`6ba00241bbf33bd4a4937e6e31d3a76d561c5701bff629320d538566c2ba779b`.

A separate five-variant test of shortening the cached particle style lifetime
is rejected. Both compiling declaration-move interactions lose 194.1816
weighted bytes and eight aligned references; no style spelling is retained.
That complete negative sweep has spec SHA
`0da830615973e9e4cbe51a0b243cb91de7bdd0a54579803d5029b7c9cdac1c2e`.

Together the two retained refinements improve the update from 50.0344590% to
50.1722950%, from 4,207.3977 to 4,218.9883 weighted bytes, and from
`356/0/27` to `358/0/24` references while ending at the same 2,150/2,203
instruction count. The final fuzzy gap is 4,190.0117 bytes. The 27-record
`experiments.jsonl` SHA-256 is
`20047e30dd300664f9d4b8dbbdbf6170a3eb796c24c1b833ee01cc5d98e742a6`.

## Secondary-impact control-flow and lifetime recovery

A fresh live Binary Ninja pass against target
`3023:2:9499448411019345244` selected the previously unworked secondary
projectile phase at `0x00421d68-0x00422435`. Two complete negative matrices
first bounded the tempting trail-local hypotheses:

- Native `0x00421d68-0x00421da6` clears the two velocity sign bits before
  updating the trail timer. All 11 scalar, bit-local, and inline-helper
  spellings either compile byte-identically or lose at least 139.9093
  weighted bytes. The recorded spec SHA is
  `367ee16aa2e715a41b98b73b72098fe5b6ba5a9291a74815195087b9e47da9a5`.
- Native `0x00421db7-0x00421e39` stages the trail-position trigonometry through
  stack temporaries. Seven named-scalar and aggregate spellings are
  byte-identical at best; the byte-neutral forms worsen reference alignment,
  while the aggregate forms lose more than 208 weighted bytes. The recorded
  spec SHA is
  `4e6ef65f83095db0fe33adee7f60f64440c383d697df043f141f1e7d39255a33`.

No trail source change is retained. The next native regions instead exposed
several source-precision corrections:

- At `0x004220b9`, native loads `frame_dt` and emits `fdivr 1.0f`. Staging the
  denominator before taking its reciprocal reproduces that instruction pair.
  Four equivalent float spellings tie at +3.8635 weighted bytes; the shortest
  two-step spelling is retained. The five-variant spec SHA is
  `8453493c91cf8c881ef4418766f140e86c7daed6b863d8d321a1ac3f1295b184`.
- Native reloads the secondary projectile type at `0x0042200f` before damage
  selection and again at `0x004220f0` after `creature_apply_damage`. Restoring
  both reads adds 13.5370 weighted bytes, removes two candidate instructions,
  and adds one aligned reference. Either reload alone is a large regression,
  so the complete three-variant interaction result is essential evidence.
  Its spec SHA is
  `62fe51121e9bbeef5568731000cc68164a22df29eebab6f977cc7ad65e0a60f3`.
- From `0x004220ff` through the three rocket-type arms, native places each
  freeze-shard path first and branches to the decal path. Rewriting the three
  semantic-equivalent tests as positive `bonus_freeze_timer` checks recovers
  139.1515 weighted bytes in the full seven-variant matrix. The spec SHA is
  `8f522bf2429a8009131688d06ad3448196b226800794a99ef3ba54f17a154007`.
- The earlier hit-entry split at `0x00421e9f` has the same native branch
  order. Reordering it and spelling the native detail threshold as
  `config_detail_preset >= 3` adds another 77.3064 weighted bytes. Both
  changes are independently positive; the complete interaction spec SHA is
  `f17a2a43385a381fa6e801abfc0c1327cbb671e15e4d82e3f73acbbf04899e38`.
- Native reloads `bonus_freeze_timer` inside each selected type arm rather
  than keeping one value across the dispatch. Replacing all three uses and
  deleting the dead hoisted local adds 11.5960 weighted bytes, improves the
  aligned audit from `367/0/29` to `375/0/24`, and keeps the instruction
  count unchanged. The full seven-variant spec SHA is
  `59dc5a33c1ec2282fd17febfe9272dcfd1d7c37855f9e61da834328b717a2c0a`.
- In the final impact burst at `0x004223ec-0x00422412`, native materializes
  both trigonometric results before scaling the velocity. Naming both scalars
  is the unique best semantic form: +8.7587 weighted bytes and one fewer
  candidate instruction, with no reference delta. The six-variant spec SHA
  is
  `a514d0eb6c8f872e804c2e3ab7f5e243e39b963365206a33fb305a05eb2f7ba6`.

All 49 planned variants across the eight sweeps completed without truncation.
Together the retained changes raise `projectile_update` from
`4218.9883/8409` to `4473.2014/8409` fuzzy-weighted bytes
(`50.1722950%` to `53.1954023%`), reduce the fuzzy gap by `254.2131` bytes to
`3935.7986`, and move the candidate from 2,150 to 2,147 instructions.
References improve from `358/0/24` to `375/0/24`. The final source SHA-256 is
`c9357403c5b816fc757f83171d17cb8de7358ec60444b401508e70b769ff066d`;
the 35-record `experiments.jsonl` SHA-256 is
`e73023e3e525f6c66fdc802262bcb018054cd0c8da49cac85078a3353d4aeb7e`.
