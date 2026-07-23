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

It produces 2,131 instructions against 2,203 native instructions, scores
46.75%, and aligns 333 candidate references. The candidate's natural local
frame is `0x98`, while the native function uses `0xf4`.

## Binary Ninja evidence

Live disassembly confirms that the initial movement budget is
`(int)travel_budget`, doubled through an x87 integer-to-float round trip when
Barrel Greaser is active for a player-owned projectile. Each microstep adds
`cos/sin(angle - pi/2) * frame_dt * 20 * speed_scale * 3`, flushes the
accumulator at length 4 or near the loop tail, and advances the logical step by
three.

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

## Remaining work

The native behavior is substantially represented, but whole-function MSVC
scheduling still differs. In particular, the native `0xf4` frame reuses many
long-lived vector temporaries across projectile and particle branches, whereas
the recovered structured source naturally compiles to `0x90`. Further work
should improve original declaration/lifetime shape only when supported by
control-flow evidence. No dummy locals, volatile expressions, forced
references, inline assembly, or layout-only gotos are used to imitate the
native frame.
