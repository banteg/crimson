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

## Primary-impact control flow and destination lifetimes

The next live Binary Ninja slice selected the largest untouched primary-impact
region at `0x004212ff-0x00421667`: 872 native bytes, 318.5761
fuzzy-weighted bytes, and a 553.4239-byte local gap at the starting
checkpoint. The native disassembly artifact has SHA-256
`a8884ec43c287a1b150de3a7b39cb0ff85d895b16015ccf8b1017b2cfe6523d3`.

Four source-level corrections are retained:

- At `0x004214d9-0x004215a7`, native handles the positive remaining-damage
  branch first. It keeps the raw cosine and its first speed-scaled component
  live across the comparison, then scales the same cosine again for the
  second impulse component. Spelling that control flow and lifetime directly
  adds 10.5572 weighted bytes and one aligned reference after the presentation
  branch correction. Float and double cosine locals compile byte-identically;
  the float form is retained. The complete seven-variant matrix was repeated
  after the independent branch change and has spec SHA
  `1feb3525f418443512e439cb4f5deea5db76e236f7f1ad356bb5b4ed3489089d`.
- At `0x004215a7-0x004215c6`, native loads `life_timer` directly, compares its
  word to `0.25f`, clears `damage_pool`, and skips the lifetime write on the
  equal arm. Removing the recovered float copy and expressing that equal arm
  first adds 16.5062 weighted bytes and removes one candidate instruction.
  The four-variant spec SHA is
  `1907259452289551b78978684ed3e31f39e72ffca4038584bd8b4c8c854e3eec`.
- At `0x004215e7-0x0042174e`, native emits the positive Freeze-shard arm
  before the three-decal arm. Restoring that semantic branch order adds
  46.3945 weighted bytes and four aligned references without changing the
  instruction count. The one-variant spec SHA is
  `4824249352cd201ac701f44f02f93cbcc9652b9b68aa693136da5db9c4aef012`.
- At `0x004216a2`, `0x004216dc`, and `0x00421716`, native materializes the
  1.5x, 2x, and 2.5x decal positions in three distinct vectors (`pos_3`,
  `pos_2`, and `pos`) before the queue calls. Replacing the reused source
  destination with those three real objects is the dominant geometry gain.
  Two equivalent initializer/component spellings tie at +54.4661 weighted
  bytes over the intermediate aggregate candidate; the shorter initializer
  form is retained. This leaves the final source 81.1903 bytes above the
  pre-geometry checkpoint, removes one reference mismatch, and adds three
  aligned references. The four-variant destination spec SHA is
  `4d775ddebbaa2c5a406abbe0f99342c4e3ca9e514516449a08d1aa35486d18b5`.

The complete 63-variant precursor matrix showed that temporary scale vectors
for the 2x and 2.5x calls could add 26.7242 weighted bytes while the source
still reused one destination. The distinct-destination sweep superseded that
intermediate shape: keeping both scale and destination aggregates regressed,
while three destinations with direct scale expressions produced the final
best result. That interaction record has spec SHA
`a01ac81e87e707a822aecff8f8c3c6e588f0888f64e04adb032e26222f54e558`.

A separate complete 19-variant matrix rejected Plasma Cannon child-position
and Pulse Gun displacement scalar staging. The native-looking single-site
forms compile byte-identically; broader aggregate interactions only worsen
reference alignment. No such source change is retained. Its spec SHA is
`0c9fc7383bd79968e64fb355e5b60156a4088f97d507872812ef66be256c67b3`.

Across the seven recorded sweeps, the retained source raises
`projectile_update` from `4473.2014/8409` to `4627.8497/8409`
fuzzy-weighted bytes (`53.1954023%` to `55.0344828%`), reducing the fuzzy gap
by `154.6483` bytes to `3781.1503`. The final candidate remains
2,147/2,203 instructions; references improve from `375/0/24` to `384/0/22`.
The final source SHA-256 is
`9167b70853189b69596734e8f7cd7d981989846ff8286cc6a45923015cf8e14f`;
the 42-record `experiments.jsonl` SHA-256 is
`a243427f9fd9e3fad30978a7d25e272a0c37a73d37950279c3ba9c31ed7d9be9`.

## Secondary-explosion x87 lifetime and cursor audit

Live disassembly of `0x00421a0d-0x00421b9d` exposed two native induction
variables and an x87 lifetime difference in the secondary-projectile
explosion path. Four complete sweeps separate the independently useful source
shape from attractive but audit-regressive interactions:

- The seven-variant distance-lifetime sweep found one clean correction.
  Copying `dx` before the squared-distance expression makes MSVC duplicate the
  x87 value as native does, adds 6.6670 fuzzy-weighted bytes and one candidate
  instruction, and preserves all `384/22/0` ok/mismatched/unresolved
  references. Its spec SHA is
  `e4cb6c063fbbe2694cfdd9ad268a28a4495ae686f4cd4a0085e1d8b04e00691b`.
- The seven-variant follow-up closed alternate copy and operand orders.
  Commuting the retained operands is byte-neutral; adding another explicit
  copy removes the recovered instruction or worsens reference alignment. Its
  spec SHA is
  `33c9c35a3a1093716f0f1095b28c2884881317ddf9432b792caa735889f14704`.
- Native carries the secondary cursor at `velocity.y` and the creature cursor
  at `position.y`, so the exhaustive 15-variant cursor interaction tested both
  interior cursors with their required record strides. The fully valid
  interaction gains 95.9090 weighted bytes but removes ten candidate
  instructions and changes references from `384/22/0` to `373/23/0`; it is
  rejected. The nominal 133.5529-byte winner is semantically invalid because
  its creature cursor never advances, so its score is not actionable. The
  interaction spec SHA is
  `9e7fd43a5e8015a70b21ebe4282c9a1d7f732e7f26c56666021743db85bbb2fe`.
- Native also loads `frame_dt` once and duplicates it across the secondary
  movement update. All three equivalent named-`dt` forms gain 3.8653 weighted
  bytes but change references from `384/22/0` to `381/25/0`; none is retained.
  The five-variant spec SHA is
  `bad3e20f79f2fe0c03b4303fb079e66298fd2067c110f1f579dc55cb11c6eb15`.

The retained lifetime correction raises `projectile_update` from
`4627.8497/8409` to `4634.5167/8409` fuzzy-weighted bytes
(`55.0344828%` to `55.1137670%`), reduces the gap to `3774.4833`, and moves
the candidate from 2,147 to 2,148 of 2,203 target instructions without
reference debt. The final source SHA-256 is
`605d117e2a187047317a78498b8b050be4ddf781a340ef38ec76e9fb1d47b584`;
the 46-record `experiments.jsonl` SHA-256 is
`ecd0768ac21e0442c156d222499716f309417fede665ebd4eb5c474808a28057`.

## Ion-chain creature ownership

The next unworked native seam was the Ion Rifle chain transition at
`0x00421218-0x0042130b`: 243 target bytes with a 110.4545-byte localized gap.
Native computes the next-creature record address once and retains the hit
creature as a separate owner while forming the X/Y differences for `fpatan`.
The recovered source instead repeated four indexed `creature_pool` expressions.

`primary-ion-chain-geometry-mutations.json` evaluates eight pointer, scalar,
and aggregate spellings. Five pointer-owner forms compile to the same dominant
instruction improvement. Retaining explicit `next_creature` and
`hit_creature` pointers gives the best reference explanation among them: it
adds **139.1515 fuzzy-weighted bytes** without changing the 2,148-instruction
candidate, and raises aligned references from 384 to **397**. Mismatches rise
from 22 to 24 because the improved alignment exposes the remaining local x87
operand schedule; unresolved references remain zero. The sweep spec SHA-256 is
`1e52cc4281efe0fc7d038c0e7f3d3b549bc58e82e3063060296a7fc71306a631`.

Two complete follow-ups bound that residual:

- All seven creature/position pointer and reference-type refinements are
  byte-neutral at best. Creature references and const creature pointers also
  preserve the `397/0/24` audit exactly; position-typed owners lose one to
  three aligned references. The spec SHA-256 is
  `925e29b3b19f6b25aa988872f6b7a761cd62782852f8c981bcd305a83867a6b7`.
- Eight natural operand-order forms do not recover native's x87 schedule.
  The nominal aggregate winner adds only 2.7675 weighted bytes while adding
  one instruction, losing one aligned reference, and adding one mismatch, so
  it is rejected. Negating reverse subtractions removes the three local
  mismatches but loses 17.6474 weighted bytes and adds two non-native
  instructions; that artificial tradeoff is also rejected. The spec SHA-256
  is
  `1f2ddfc9c386292b65e93f15af07cb98c42a2e59985c378698bb2825bf376eba`.

The retained candidate loads Y then X and executes `fpatan` directly; native
loads X then Y, executes `fxch`, and reaches the same `atan2(dy, dx)` result.
The two swapped leaf references and the adjacent address-owner reference are
therefore an explicit compiler-evaluation residual, not hidden reference debt.
The overall result rises from **55.1137670%** to **56.7685590%**,
`4634.5167/8409` to **`4773.6681/8409`** weighted bytes, with a
**3635.3319-byte** gap and unchanged 2,148/2,203 instructions. The final source
SHA-256 is
`c7002fb41ee645d9240e9df53c4c90466ea7f9a2691cb03553f8fd325724c2af`;
the 49-record `experiments.jsonl` SHA-256 is
`63ce3461dd936953b0160a02a3c148b10402333a67a3dd16198eb4ee75fab6b8`.

## Particle expiry control and owner lifetimes

The next pass returned to the low-alignment particle movement/expiry region at
`0x0042241c..0x00422782`, but selected the previously untested expiry suffix at
`0x004226af`. Native tests the cached style before choosing the `0.0f` or
`0.8f` intensity comparison, then reloads the attached target only at the
death call boundary.

Two source corrections are retained:

- `particle-expiry-control-mutations.json`
  (`dcdee8e5a036888953e42c414b48bb5d1f9a6f85c5978e544d7cbb291fe5d025`)
  evaluates all 8/8 equivalent predicate and threshold shapes. Putting the
  nonzero-style arm first is the unique clean winner: it adds 45.2763 weighted
  bytes, adds one candidate instruction toward the 55-instruction native
  deficit, and removes one reference mismatch.
- `particle-expiry-target-lifetime-mutations.json`
  (`89251c6b768555f5cc84e8e60c4ebced25fd3ee6ad94f602b185cdd186118ec1`)
  evaluates all 6/6 direct, reloaded, and creature-owner lifetimes. Reloading
  `particle->target_id` only for `creature_handle_death` adds another 10.4836
  weighted bytes and one native-shaped instruction with no reference
  regression. Reloading across the preceding SFX path is measurably worse.

Two follow-up matrices bound the tempting SFX call-evaluation interpretation:

- `particle-expiry-sfx-evaluation-mutations.json`
  (`2b357e972704b732d113b7507deefad221b0fa2abc887ed44c3a17b73db4f6e2`)
  evaluates all 4/4 inline/local call shapes. The nominal 43.0045-byte winner
  adds four reference mismatches, so it is rejected.
- `particle-expiry-sfx-owner-mutations.json`
  (`da84fa69d77435c8f19f01043e724b6fb454855fc3cd2d83911c84a189008047`)
  evaluates all 6/6 retained/reloaded type and position owners. Its nominal
  39.1436-byte winner still adds three mismatches; no SFX form is retained.

Together the two accepted changes raise `projectile_update` from
`4773.6681/8409` to `4829.4280/8409` weighted bytes
(`56.7685590%` to `57.4316563%`), reduce the gap by 55.7599 bytes to
3,579.5720, and move the candidate from 2,148 to 2,150 of 2,203 native
instructions. References improve from `397/0/24` to `397/0/23`. The retained
source SHA-256 is
`353b8c1b0cc3e7b0d7a4063a9e39a7c2e155011c7e62f8df5c29ad88bb2131d5`;
the 53-record `experiments.jsonl` SHA-256 is
`3919343e81673f26683751ec18cdb633a8f06f9598380c3887dd6ed19b5af2b1`.

## Particle steering allocator boundary

The three style-specific steering arms at `0x00422775..0x0042283d` share one
remaining native/candidate lifetime difference: native retains each updated
angle on x87 for `fcos`, stores it directly to the particle, and reloads the
field for `fsin`; the candidate also materializes a stack copy. Two complete
sweeps bound the natural source controls:

- `particle-steering-assignment-mutations.json`
  (`403314614eb539f9587e6d73f2c22393ad5f4f7a2d206e3b3084895d6dede224`)
  evaluates all 7/7 single, paired, and triple compound-versus-direct
  subtraction assignments. Every combination is byte-identical.
- `particle-style-eight-steering-lifetime-mutations.json`
  (`5ae1a9ef3d4d9d533715de53f846127097773d72165088b751bfd9d160a76523`)
  evaluates all 6/6 explicit float, pointer/reference owner, named-angle, and
  inline-turn lifetimes on the unique speed-62 arm. The nominal 3.8635-byte
  forms lose aligned references and add four to seven mismatches. The
  reference-clean owner forms remove two candidate instructions, moving the
  already-short candidate farther from native, so none is retained.

The spill is therefore coupled to whole-function allocation rather than the
local assignment spelling. Source and metrics remain unchanged at
57.4316563%, 2,150/2,203 instructions, and `397/0/23` references, with source
SHA-256
`353b8c1b0cc3e7b0d7a4063a9e39a7c2e155011c7e62f8df5c29ad88bb2131d5`.
The 55-record `experiments.jsonl` SHA-256 is
`89ee2569be476e9261ae68f00563d761be1b14858b498f95f5dbc08e5b0991c4`.

## Particle style phase-boundary reloads

The remaining movement residual at `0x00422500..0x004226af` was separated
from the already-bounded expiry and steering suffixes with five complete
sweeps covering 79 variants. Native reloads the style byte at the death gate
(`0x004226e8`) and again after the radius query at the collision gate
(`0x004228a7`), while the candidate had kept the original cached byte live
across both phase boundaries.

Two direct field reads are retained together:

- `particle-style-phase-lifetime-interactions.json`
  (`e0339ad0f59b511ed47fe51f5d42fe0fa5541113c0beebe98801ac6bbc76818d`)
  evaluates all 15/15 movement, expiry/steering, death, and collision
  lifetime interactions. Reloading only the death and collision gates is the
  unique clean improvement: it adds 1.6439 weighted bytes and two candidate
  instructions without changing the `397/0/23` reference audit. Splitting
  the movement and expiry/steering owners instead loses 59.6252 weighted
  bytes, six aligned references, and two instructions.
- `particle-style-owner-phase-mutations.json`
  (`1a643bf671b609d8a2d97bba4d0d34d9480cb5e4de761f824b49ad9e7f142e5d`)
  independently evaluates all 31/31 combinations of direct field reads
  across the five style-use phases. Its nominal 22.0667-byte winner loses
  three aligned references and adds four mismatches, so the broader rewrite
  is rejected.

Three movement-shape controls are also rejected:

- `particle-movement-threshold-order-mutations.json`
  (`3aece617353e5c3718f0998a85d69d54867710502c9bf57f9ce6e99ec07a9b29`)
  evaluates all 3/3 high-intensity-first branch interactions. The style-eight
  rewrite is byte-identical; the default-arm rewrite gains 7.7271 weighted
  bytes but adds two reference mismatches.
- `particle-low-movement-staging-mutations.json`
  (`f31a0468b9b7300dea7e8d51e243f896c5a19c18a85ba92b550b315209dfe31d`)
  evaluates all 15/15 scalar and vector staging forms, then repeats all 15
  after the accepted reload pair. The repeat's nominal 60.6650-byte winner
  adds five reference mismatches. The reference-clean forms are all neutral
  or negative, so no displacement staging is retained.

The accepted pair raises `projectile_update` from `4829.4280/8409` to
`4831.0719/8409` weighted bytes (`57.4316563%` to `57.4512055%`), reduces
the gap to 3,577.9281 bytes, and moves the candidate from 2,150 to 2,152 of
2,203 native instructions with references unchanged at `397/0/23`. The
retained source SHA-256 is
`4eaf3f0b9ac959a68d5858a2e8364557b0f81c5e37a7629603ad235bfd754f23`;
the 60-record `experiments.jsonl` SHA-256 is
`56a567e472231377ef164a39e5aa230b619ebef651aafb3be630483cfea5eca9`.

## Particle steering factor staging

Live native disassembly at `0x00422775..0x0042283d` keeps all four
multiplications in each style-specific turn calculation: `0.06f`, intensity,
`frame_dt`, and the final `1.96f` or `1.1f` factor. The former single
expression let VC6 combine the two constants and emitted only three
multiplications per arm.

`particle-steering-factor-staging-mutations.json` (SHA-256
`2de36b944ab891a65e856ec22155bec5e0874a6c847e353acd28c33af92da0fb`)
exhausts all 215 single-, double-, and triple-site combinations of five
ordinary factor-lifetime spellings across the style-zero, style-eight, and
default arms. Staging the four factors as successive updates to a
branch-local `turn_delta` is the best reference-clean interaction. Although
the style-eight and default forms regress in isolation, retaining all three
together adds 8.2517 fuzzy-weighted bytes, three candidate instructions, and
six aligned references while removing three mismatches.

The canonical result rises to `4839.3235/8409` weighted bytes
(`57.5493346%`), reduces the gap to 3,569.6765 bytes, moves the candidate to
2,155/2,203 instructions, and improves references from `397/0/23` to
`403/0/20`. The retained source SHA-256 is
`d90b2a4f66c78e180738a4d51ba1614958d4f7ccc17377dbc5585c3857a4e90b`;
the 61-record, 718-variant `experiments.jsonl` SHA-256 is
`48dc4299a1b09391622837b8ab75c61da8ca07688eb19195c3a986b7cc8d6728`.

## Particle age selection boundary

Native `0x0042283f..0x0042285a` keeps the selected age value on x87 across
the intensity comparison and performs one final store. The canonical
if/else instead materializes the intensity arm with an integer move.

`particle-age-selection-mutations.json` (SHA-256
`4c91fe94730ef563c37ebd2a1c204afb8853bd82206bc35abd0a057806094de1`)
exhausts all 12 ordinary direct-ternary, named-result, cached-intensity, and
assign-then-clamp spellings. The five result-selection forms each gain
3.8591 fuzzy-weighted bytes locally, but all add three reference mismatches
and lose two aligned references. Clamp forms also move the candidate one or
two instructions farther below native. No form is retained.

This bounds the age residual as coupled to the whole-function allocator
rather than the local selection spelling. Canonical metrics and source remain
unchanged at `4839.3235/8409` weighted bytes (`57.5493346%`),
2,155/2,203 instructions, and `403/0/20` references, with source SHA-256
`d90b2a4f66c78e180738a4d51ba1614958d4f7ccc17377dbc5585c3857a4e90b`.
The 62-record, 730-variant `experiments.jsonl` SHA-256 is
`1e7a926922fe8d60fae916048e14a04d75633cf836e926a5def3efedb8a20ca3`.

## Secondary polar-decal geometry boundary

Native repeats the same x87 schedule in the rocket, seeker-rocket, and
rocket-minigun hit loops at `0x00422197..0x004221c7`,
`0x00422280..0x004222b6`, and `0x0042236b..0x004223a1`: it stores the cosine
times radius result before evaluating sine, then adds the creature's x and y
coordinates. The canonical aggregate initializer instead appears to finish
the x destination before beginning the y expression.

`secondary-polar-decal-geometry-mutations.json` (SHA-256
`faa08ed013708b4e907354a07bd964489ff377e0265f59868ed0e9082b0aa533`)
exhausts all 215 single-, double-, and triple-site combinations of named x
components, sequential destination assignments, named x/y components,
offset aggregates, and separately named cosine values. None improves the
canonical score or reference audit. Several combinations compile
byte-for-byte identically; all other forms regress, and there are no
tradeoff variants.

The apparent three-site reference alignment is therefore not controlled by
these local source lifetimes. Canonical metrics and source remain unchanged
at `4839.3235/8409` weighted bytes (`57.5493346%`), 2,155/2,203
instructions, and `403/0/20` references, with source SHA-256
`d90b2a4f66c78e180738a4d51ba1614958d4f7ccc17377dbc5585c3857a4e90b`.
The 63-record, 945-variant `experiments.jsonl` SHA-256 is
`19f6533e1ec29c0de4c57865e530f33462392baff258915598b2da09e3521919`.

## Render-pool induction-anchor boundary

Live native disassembly identifies two later pool anchors precisely. The
sprite-effect loop loads `sprite_effect_pool[0].position.y` at `0x0042246a`
and uses 0x2c-byte strides; the particle loop loads
`particle_pool[0].velocity.y` at `0x004224f0` and uses 0x38-byte strides.
The canonical candidate instead lets VC6 choose nearby interior anchors.

`render-pool-interior-cursor-interactions.json` (SHA-256
`51b7ab5f7d6b3d6f09ba2f94afd7ef782446ca4db456ca81e365d80e839128bc`)
evaluates all 15 declaration, stride, loop, and cross-loop combinations.
Forcing the exact sprite position-y cursor is byte-neutral but loses three
aligned references and adds three mismatches (`400/0/23`). Forcing the exact
particle velocity-y cursor adds four candidate instructions but loses
54.5601 weighted bytes, nine aligned references, and four mismatches
(`394/0/24`). Combining the two loops does not recover either regression.
No form is retained.

The remaining pool-address audit entries therefore reflect whole-function
register allocation and SequenceMatcher alignment, not incorrect record
ownership or bounds. Canonical metrics and source remain unchanged at
`4839.3235/8409` weighted bytes (`57.5493346%`), 2,155/2,203
instructions, and `403/0/20` references, with source SHA-256
`d90b2a4f66c78e180738a4d51ba1614958d4f7ccc17377dbc5585c3857a4e90b`.
The 64-record, 960-variant `experiments.jsonl` SHA-256 is
`eb7bcc6263b1e24baef730a3f0bae4441032e953df59fc4dead52059007c4c3a`.

## Seeker and smoke vector house style

The recovered SDK `vec2_t` establishes the source idiom behind the large
secondary-projectile residual: two-float constructors, temporary-returning
subtraction and scalar multiplication operators, `VEC2_Angle`, and the
bit-mask `m_fabs(float)` helper. Native `0x00421c87..0x00421e68` independently
shows each consequence. The seeker direction evaluates x before y and uses
`fxch` before `fpatan`; acceleration and clamping reload the stored heading
for each component; the trail timer clears sign bits through integer masks;
and smoke position construction materializes the cosine before sine and then
applies the scalar/vector subtraction.

The matching source now uses a layout-compatible local vector class for the
direction and smoke temporaries, keeps the velocity component updates direct,
and restores `m_fabs`. This raises the canonical result by 246.5322 weighted
bytes to `5085.8557/8409` (`60.4810997%`), moves the candidate from
2,155 to 2,162 of 2,203 instructions, and improves references from
`403/0/20` to `408/0/19`. The retained source SHA-256 is
`d19d18a72f4955ad49d2de0594c1ccbc72c1605d72e89304eb5c6ee08eb988aa`.

## Pool movement vector house style

The recovered SDK's update loops consistently spell two-component motion as
`position += time * velocity`. Applying that idiom to the secondary-projectile
movement, sprite-effect movement, and the style-eight low-intensity particle
arm recovers the corresponding constructor, scalar-multiply, and compound-add
x87 schedules. The three sites interact through VC6 allocation: together they
also improve the static-reference alignment, rather than merely shifting stack
temporaries.

The retained source raises `projectile_update` by 112.8544 fuzzy-weighted bytes,
from `5085.8557/8409` to `5198.7101/8409` (`60.4810997%` to
`61.8231666%`), and moves the candidate from 2,162 to 2,174 of 2,203 native
instructions. References improve from `408/0/19` to `416/0/18`. Equivalent
operator forms in the two high-intensity helper arms, the default
low-intensity arm, collision geometry, velocity scaling, Pulse Gun knockback,
and the final hit-creature displacement were measured individually and in the
relevant interactions; all were neutral or regressive and are not retained.
The retained source SHA-256 is
`f283368028c152aa81044e3a1fd17fc2a5fcc22a375bc248eac1c9e50e47fa59`.

## Bloody Mess offset and destination vectors

After excluding the completed primary-microstep and particle movement/
collision-owner families, the highest uncovered region was native
`0x004210a6..0x00421201`. Its Bloody Mess loop does not add each random
component directly to the hit creature position. At
`0x004210ce..0x00421183`, native first converts both random offsets, then
constructs a distinct destination vector by adding the creature position;
it repeats the same two-vector boundary for the second queue call.

The matching source now transfers the already-confirmed secondary direct-hit
house style to these two calls: each has a separately named offset and
destination vector. This is a source-lifetime recovery, not an address or
register-forcing device. It raises the whole-function weighted result from
`5198.7101/8409` to `5269.3071/8409` (`61.8231666%` to `62.6627084%`),
adds two candidate instructions (`2174` to `2176` of `2203`), and improves
references from `416/0/18` to `417/0/18`. The selected region rises from
145.5161 to 151.3511 weighted bytes. The retained source SHA-256 is
`3c354f7b530d8308e7cab67ae303a1b4f219b0df3ee869c38d0d5b364adbb923`.

## Structural residual handoff (2026-08-13)

The current candidate allocates `0xc4` bytes in its prologue while native
allocates `0xf4`, a native-minus-candidate delta of `+0x30`. This is the first
mismatch and is a whole-function allocation signal, not evidence for twelve
missing four-byte source locals. The verified VC6 listing makes that warning
concrete: 80 named/generated aliases collapse onto 28 distinct stack slots,
24 of those slots are reused, and only eight aliases are compiler-generated
temporaries.

CFG alignment is structurally close but still incomplete: native/candidate
have 287/283 blocks, with 76 unique exact pairs, 45 duplicate-exact pairs,
95 similar pairs, and 71/67 unmatched blocks. All 76 unique exact pairs survive
the order-bounded anchor filter. There are no anchored edge conflicts; the two
conflicts produced by greedy non-unique pairing are heuristic only.

The largest unmatched target island, block 97 at
`0x0042163d..0x0042174e`, is the already-recovered three-decal loop. Native
materializes the scaled X/Y pair before each of the 1.5x, 2x, and 2.5x
destination vectors. Because the earlier scale-vector experiment predated the
current three-destination source, the schema-1
`primary-decal-scale-replay-mutations.json` plan replays every subset on the
current baseline. Its SHA-256 is
`391f9e3a225d2d2c3e537339670726df617059f3d2cfa5220da8c1db65e5e5db`.

All 7/7 variants completed. Each single-site form gains a small amount of
fuzzy weight (`+9.1110`, `+5.2722`, and `+5.2722` bytes) but worsens references
from `417/0/18` to `416/0/20`. Two-site interactions lose between `100.7363`
and `119.9218` weighted bytes, and the native-looking all-three form loses
`172.1300` while references fall to `405/0/20`. There is no tradeoff-free
winner, so the source remains unchanged. The updated `experiments.jsonl`
SHA-256 is
`4701e2d756c3342893633fad8109ce9fc233097629c176e0499ef7d3ef556e11`.

The next two large unmatched islands are also closed surfaces: block 55 is the
retained Bloody Mess offset/destination split, while block 74 is the rejected
Plasma Cannon child-position staging. Block 256 is the retained particle-hit
geometry. Advice for the next agent: treat the `+0x30` frame delta as one
upstream lifetime clue, but do not add or hoist locals merely to reach `0xf4`
and do not reopen these ranked islands without new native evidence. A fresh
hypothesis should start outside the covered decal, Plasma-child, and particle
geometry regions and must improve its bounded region without trading references
or already-matched blocks.

## Primary-impact jitter lifetime boundary

The next uncovered native fragment at `0x004211b8..0x004211ee` keeps the
primary-impact jitter integer in a stack slot, converts it with `fild`, and
reuses the converted value across the cosine and sine position updates. The
current source's ordinary `int jitter = crt_rand() & 3` instead lets VC6 load
the heading before materializing the integer, so this was a concrete x87
lifetime hypothesis rather than a frame-size guess.

Three complete plans close the local surface. The 5/5 lifetime sweep (spec SHA
`3affdcc608216d87b02ac1d7902aa5f4423ff565cb2e2ec457cc9fe7640b1446`)
found that `double jitter` gains 11.2989 weighted bytes and preserves
references at `417/0/18`, but removes three candidate instructions from an
already-short `2176/2203` build. Float and named-conversion forms gain only
5.0451 bytes, remove one instruction, and the latter forms also worsen
references. Its one compile failure was an invalid vector `+=` spelling for
the plain `vec2f_t` reconstruction and is digest-bound by mutation-error audit
record 69.

All 4/4 operand-order variants compile identically to `double jitter` (spec
SHA `6a93b175aa7ec86ce0ee83570635f4451628c40b40cbe4d694e159271200ecc4`),
so reassociation does not recover the missing native operations. A complete
15/15 interaction sweep against the three native-looking decal scale vectors
(spec SHA
`40c6463c12b2d09f32e5a12d5ab460caee3361a81e5d4c7fc8d5f724668d6af2`)
raises the best fuzzy delta to 20.4110 bytes, but still removes one instruction
and worsens references to `416/0/20`; larger combinations regress sharply.

No form is retained. The canonical result remains `5269.3071/8409`
(`62.6627084%`), `2176/2203` instructions, and `417/0/18` references with
source SHA
`3c354f7b530d8308e7cab67ae303a1b4f219b0df3ee869c38d0d5b364adbb923`.
The recorded evidence log SHA is
`faf9651342c6d65877064cb7c8dbabe5e6138db55ed63d4db628e29756dfddb7`.
Do not retain the attractive `double` form unless a separate native-backed
change recovers the three lost instructions without degrading references.
