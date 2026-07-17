# `projectile_update`

The current MSVC 6.5 `/O2 /GB` candidate recovers the complete primary
projectile-pool phase at `0x00420b90`: active/lifetime handling, lingering ion
and Gauss damage, world-bounds expiry, travel-budget microsteps, creature and
player collision, perk hooks, projectile-specific hit behavior, penetration
damage, decals, freeze effects, and impact audio.

It produces 963 instructions against 2,203 native instructions, scores 26.22%,
and resolves 126 candidate references. The candidate's natural local frame is
`0x88`; the native function's `0xf4` frame also carries the still-missing
secondary-projectile and trailing effect-pool phases.

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

## Remaining work

The 64-entry secondary projectile simulation, its explosion and homing paths,
and the trailing sprite/effect maintenance loops remain unrecovered here. The
primary loop also retains scheduling and stack-slot differences expected from
those absent later lifetimes. No dummy locals, volatile expressions, forced
references, inline assembly, or layout-only gotos are used to imitate the
native frame.
