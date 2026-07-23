# `projectile_render`

Native target: `crimsonland.exe` at `0x00422c70` (12,551-byte manifest
extent).

The recovered callback owns a sequence of separately batched visual passes:
Sharpshooter laser sights, conventional bullet trails, the selected player's
muzzle flash, five plasma-family trail styles, primary projectile sprites and
ion/fire beams, Plague Spreader clouds, Fire Bullets overlays, small projectile
billboards, and three secondary-projectile passes.

Live Binary Ninja evidence establishes that plasma trail length converts the
origin-to-position distance and `speed_scale * spacing` to signed integers
before dividing and applying the per-type cap. It does not use the simulation
travel budget. The secondary 140px bloom pass likewise visits every active
secondary entry before the later type-specific sprite and glow passes, so it
also applies to the exploding state. Both findings are recovered in the modern
renderer with focused tests. The later bullet-billboard pass excludes only
Plasma Rifle, Plasma Minigun, and Pulse Gun, preserving a 4px core for
Shrinkifier, Spider Plasma, and Plasma Cannon; that omission is recovered too.

The scratch deliberately retains strict `life_timer == 0.4f` branch tests,
the separate detail-gated passes, the native integer conversions, and the
Plague Spreader's asymmetric trigonometric offsets. Native control flow also
proves that the five plasma styles independently spell out their distance,
trail, head, and aura work. The recovered source now follows the observed
Rifle, Minigun, Cannon, Spider Plasma, Shrinkifier branch order and preserves
Plasma Cannon's asymmetric 3.5 count divisor versus 2.6 step spacing.

The ion/fire family likewise has separate live and fading arms. In particular,
the live arm sets atlas frame (2, 2) before recomputing frame (4, 2), while the
fading arm applies rotation before drawing the trail. The bullet billboard,
secondary sprite, and secondary glow passes use direct per-type draw arms
rather than parameterized sizes and colors.

The native callback's geometry is built from the game's two-float vector type,
not from independently named scalar coordinates. Live Binary Ninja IL and
disassembly establish the important object lifetimes: all four Sharpshooter
quad points are materialized before the perk gate; each conventional-bullet
type constructs its current point, origin point, half-width, and four output
points within its own branch; and the fading ion-chain arm constructs a
normalized perpendicular, its camera-space endpoints, and four strip points.
After drawing the 10-unit strip, native mutates those same four points by four
more units before drawing the wider 14-unit strip. The recovered source now
uses those vector operations and preserves that in-place widening rather than
recomputing unrelated scalar expressions.

Those source-shape recoveries raise the honest build from 33.68% to 39.77%.
The candidate now has 2,792 normalized instructions against 3,021 target
instructions, with 301 proven, zero unresolved, and 30 mismatched aligned
references. Treating the adjacent camera coordinates as the aggregate
`camera_offset` object is backed by the native symbol layout and accounts for
the formerly unresolved object-level reference without weakening reference
auditing.

The first residual remains the native 0x19c-byte local frame versus the
candidate's 0x118-byte frame. The remaining 0x84 bytes are concentrated in
other native geometry-temporary lifetimes and allocator scheduling. A natural
beam-direction/base-vector spelling was also tested because the target
materializes adjacent coordinates there, but it regressed global alignment
from 39.77% to 39.08%; the higher-scoring scalar spelling remains semantically
identical and better supported by the current compiler evidence. No dummy
locals, fake references, hard-coded addresses, or artificial register
constraints are retained.
