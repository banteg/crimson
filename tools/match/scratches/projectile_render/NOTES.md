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
Plague Spreader's asymmetric trigonometric offsets. The first complete build
is 26.35% over 3,021 target and 2,042 candidate normalized instructions, with
177 proven, zero unresolved, and 21 mismatched aligned references. Its first
residual is the native 0x19c-byte local frame versus the candidate's 0x58-byte
frame. Native code duplicates several large type-specific plasma, beam, and
secondary-projectile arms that this plausible source still shares; those
residuals are recorded honestly rather than padded or fakematched.
