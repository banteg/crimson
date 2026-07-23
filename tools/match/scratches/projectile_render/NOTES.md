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
rather than parameterized sizes and colors. Keeping those native quirks and
duplications raises the honest build from 26.35% to 33.68% over 3,021 target
and 2,692 candidate normalized instructions, with 266 proven, zero unresolved,
and 25 mismatched aligned references. Its first residual remains the native
0x19c-byte local frame versus the candidate's 0x70-byte frame; much of the
remaining delta is the original callback's extensive geometry-temporary
layout, which is recorded honestly rather than padded or fakematched.
