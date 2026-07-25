# `projectile_render`

Native target: `crimsonland.exe` at `0x00422c70` (12,551-byte manifest
extent).

The recovered callback owns a sequence of separately batched visual passes:
Sharpshooter laser sights, conventional bullet trails, the selected player's
muzzle flash, five plasma-family trail styles, primary projectile sprites and
ion/fire beams, Plague Spreader clouds, Fire Bullets overlays, small projectile
billboards, and three secondary-projectile passes.

The sole native caller pushes `ui_transition_alpha`, calls this function, and
then removes one four-byte argument. The live Binary Ninja database formerly
typed the callback as `void()` and therefore hid that argument in both caller
and callee IL; its saved prototype is now `void(float transition_alpha)`, in
agreement with the recovered source and native stack cleanup.

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
rather than parameterized sizes and colors. Native disassembly further proves
that the secondary sprite arms are an ordered `1 -> 2 -> 4` comparison chain,
while the detail-glow arms are ordered `4 -> 1 -> 2`; neither pass was a source
`switch`.

The native callback's geometry is built from the game's two-float vector type,
not from independently named scalar coordinates. Live Binary Ninja IL and
disassembly establish the important object lifetimes: all four Sharpshooter
quad points are materialized before the perk gate; each conventional-bullet
type constructs its current point, origin point, half-width, and four output
points within its own branch; and the fading ion-chain arm constructs a
normalized perpendicular, its camera-space endpoints, and four strip points.
After drawing the 10-unit strip, native mutates those same four points by four
more units before drawing the wider 14-unit strip. The secondary bloom and
three glow arms likewise construct camera-space positions by subtracting
direction vectors and scalar half-sizes. Each sprite arm first materializes
`camera + position`, sets its tint, and only then subtracts the half-size in
place. The recovered source now preserves all of those vector operations and
mutations instead of recomputing unrelated scalar expressions.

Those source-shape recoveries raise the honest build from 33.68% to 43.04%.
The candidate now has 2,839 normalized instructions against 3,021 target
instructions, with 325 proven, zero unresolved, and 28 mismatched aligned
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

## Binary Ninja type and control-flow recovery

The default analysis-time limit had left this 12,551-byte callback without
LLIL, MLIL, or HLIL. A durable `never_skip` policy now restores 214 basic
blocks. Its six major induction variables are named for the player
aim-heading, conventional-bullet velocity, plasma position, primary origin,
secondary bloom, and secondary sprite passes.

The primary projectile walks now use the existing native cursor-block types
anchored at `vel_y`, `pos_y`, and `origin_y`. This recovers enum `type_id`,
`life_timer`, `speed_scale`, origin, velocity, and tail fields without
pretending that an interior address is a `projectile_t *`. The two secondary
walks analogously use the `pos_y` block, and only fields physically before
their cursor remain negative offsets.

The recovered source now mirrors the three primary cursor lifetimes with
`vel_y`, `pos_y`, and `origin_y` views. In particular, the conventional pass
now emits the native `active - 0x1c`, `type_id + 0x4`, and `life_timer + 0x8`
layout from its induction pointer. The plasma pass also keeps its live
`life_timer == 0.4f` body before the faded arm, matching the direct native
comparison at `0x0042381b` and the fade path beginning at `0x0042407a`.
Direct primary-life comparisons agree with the corresponding
`projectile_origin_y_cursor` branches at `0x004241ae` through `0x004244b5`.

These cursor and branch-layout recoveries raise the callback from 43.04% to
44.84%, reducing the fuzzy gap from 7,149.358 to 6,923.578 bytes. The current
candidate has 2,818 normalized instructions against 3,021 target instructions,
with 358 proven, zero unresolved, and 22 mismatched aligned references. The
native frame remains `0x19c` bytes versus the candidate's honest `0x118` bytes.
