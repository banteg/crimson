# `projectile_update`

The current MSVC 6.5 `/O2 /GB` candidate recovers both native projectile-pool
phases at `0x00420b90`. The primary pool covers active/lifetime handling,
lingering ion and Gauss damage, world-bounds expiry, travel-budget microsteps,
creature and player collision, perk hooks, projectile-specific hit behavior,
penetration damage, decals, freeze effects, and impact audio. The secondary
pool covers rocket acceleration, seeker steering, smoke trails, collision
damage, detonation AoE, and type-specific debris and freeze bursts.

It produces 1,596 instructions against 2,203 native instructions, scores
37.69%, and resolves 221 candidate references. The candidate's natural local
frame is `0x8c`; the native function's `0xf4` frame also carries the
still-missing trailing sprite/particle maintenance lifetimes.

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

The secondary detonation path reuses `vel_x` as expansion time and `vel_y` as
scale, applies `frame_dt * scale * 700` damage inside `scale * time * 80`, and
keeps processing its TTL check after a hit. The latter can overwrite a freshly
selected type-specific detonation scale with `0.5`; the recovered source keeps
that observable ordering.

## Remaining work

The 384-entry sprite-effect maintenance loop and 128-entry particle simulation
remain unrecovered here. Both projectile phases retain scheduling and
stack-slot differences expected from those absent later lifetimes. No dummy
locals, volatile expressions, forced references, inline assembly, or
layout-only gotos are used to imitate the native frame.
