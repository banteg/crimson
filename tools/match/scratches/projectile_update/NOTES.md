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

It produces 2,101 instructions against 2,203 native instructions, scores
44.05%, and aligns 301 candidate references. The candidate's natural local
frame is `0x90`, while the native function uses `0xf4`.

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

The native damage impulse deliberately writes both vector components from the
same cosine term. The source retains that oddity because the disassembly and
the existing runtime parity implementation independently agree on it.

The primary impact blood branch keeps the perk-active eight-splatter path as
the native fallthrough. The perk-inactive arm branches to the two-splatter
path, which is additionally gated by the freeze timer. This condition ordering
is semantically equivalent to checking the inactive arm first, but reproduces
the native block layout without a source-level jump.

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

The live particle tail confirms three deliberately duplicated jitter branches:
style zero uses a `1.96` turn factor and speed `82`, style eight uses `1.1` and
speed `62`, and the remaining styles use `1.1` and speed `82`. A particle hit
uses radius `intensity * 8`, deflects by `1.2566371`, scales the reflected speed
by `(rand() % 10) * 0.1`, and applies `intensity * 10` damage. Creature tint is
only darkened when the RGB sum exceeds `1.6`, using
`1 - intensity * 0.01`, followed by per-channel clamping.

## Remaining work

The native behavior is substantially represented, but whole-function MSVC
scheduling still differs. In particular, the native `0xf4` frame reuses many
long-lived vector temporaries across projectile and particle branches, whereas
the recovered structured source naturally compiles to `0x90`. Further work
should improve original declaration/lifetime shape only when supported by
control-flow evidence. No dummy locals, volatile expressions, forced
references, inline assembly, or layout-only gotos are used to imitate the
native frame.
