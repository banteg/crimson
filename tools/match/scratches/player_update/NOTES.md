# `player_update` WIP

Native target: `crimsonland.exe` at `0x004136b0` (16,257 bytes).

This is the central per-player simulation routine. Live Binary Ninja evidence,
the raw Ghidra export, and the existing parity port agree on the recovered
phases:

- console short-circuit and per-player mouse/aim capture;
- previous-position capture and the dead-player timer path;
- speed-bonus application and the low-health blood/SFX pulse;
- muzzle-flash and weapon cooldown decay;
- Man Bomb's alternating eight-projectile ring;
- Living Fortress timer accumulation and 30-second clamp;
- Fire Cough's randomized fire-bullet shot and sprite flash;
- Hot Tempered's alternating plasma ring;
- the shared spread-damping scalar update;
- mouse-to-point, dual-axis, relative-direction, and keyboard movement modes,
  including acceleration, the weapon speed cap, and spawn avoidance;
- demo/AI auto-target validation plus the full 384-creature nearest-target scan
  with its 64-unit replacement hysteresis;
- demo autoplay movement, including center-orbit fallback, target pursuit inside
  the 300-unit arena radius, center return outside it, heading smoothing,
  acceleration/deceleration, weapon speed capping, and spawn avoidance;
- mouse, analog-stick, joystick-cursor, keyboard, POV, and smoothed auto-target
  aim updates;
- manual reload, Sharpshooter cooling, Anxious Loader, Stationary Reloader, and
  Angry Reloader's projectile ring;
- normal and perk-funded fire gates, Regression Bullets/Ammunition Within
  costs, muzzle smoke, projectile ownership, randomized spread, and shared
  weapon cooldown/SFX setup;
- the dedicated Fire Bullets replacement path, including its paired SFX,
  single-pellet fallback cadence, per-weapon pellet count, signed shot jitter,
  muzzle sprite, Sharpshooter spread rule, and ammo bypass;
- Alternate Weapon's complete field swap, reload SFX, cooldown penalty, and
  200-millisecond reload-key debounce;
- direct projectile dispatch for pistol, assault rifle, SMG, plasma, ion,
  pulse, blade, splitter, minigun, plague, rainbow, and Bubblegun families,
  including Shrinkifier muzzle effects and the three flame emitters;
- the Shotgun, Sawed-off Shotgun, Jackhammer, Gauss Gun, Gauss Shotgun, Ion
  Shotgun, and Plasma Shotgun pellet loops, including their per-projectile
  spread and speed randomization;
- Rocket Launcher, Seeker Rockets, Mini-Rocket Swarmers, and Rocket Minigun
  secondary-projectile dispatch, including the ammo-scaled swarmer fan; and
- movement-phase normalization, speed-bonus removal, terrain clamping, and the
  final muzzle-flash clamp.

Known missing work:

- exact local lifetimes/register allocation around the recovered control paths.

The entry death arm is now pinned across both ports. Live instructions at
`0x004136f9..0x0041372c` capture the previous position, test health, store the
float32 result of `death_timer - frame_dt * 20.0f`, and return before the
low-health, muzzle-flash, cooldown, perk, or movement phases. Python now keeps
the x87 PC=24/store boundary on the death decrement. Zig previously narrowed
that decrement correctly but decayed muzzle flash before testing health; its
preprocess path now leaves every other live-player field untouched for a dead
player.

The adjacent low-health pulse is also recovered through the three native blood
effect calls. Instructions `0x00413795..0x004137ed` evaluate
`(aim_heading + 1.5707964f) - 0.5f`, multiply both wide trig results by
`-6.0f`, add the player position, and pass that offset point to all three
calls. Both ports now preserve those PC=24 arithmetic boundaries; Zig had
previously emitted the blood effects directly at the player center.

Man Bomb stores its timer after the frame add at `0x004138d3` and after the
interval subtraction at `0x0041399d`; Living Fortress stores its timer after
the add at `0x004139d3` before comparing against 30. Both ports now preserve
those PC=24 boundaries. In particular, repeated 60 Hz updates leave Man Bomb
at `3.9999969` on frame 240 and fire its projectile ring on frame 241, rather
than accumulating host-double residue and firing one frame early.

The reload paths at `0x00415107..0x00415117` and
`0x004151e6..0x004151f6` round `reload_scale * frame_dt` at PC=24 before
subtracting it from the stored reload timer. Both ports now make that staging
explicit. Python had instead kept the scaled frame delta wide: at 38 Hz, a
stationary 1.5-second reload reached zero on frame 19, while native retains
`4.172325e-7` until frame 20. The adjacent Anxious Loader subtract/multiply,
half-reload comparison, and preload-underflow arithmetic now preserve the same
observed boundaries.

This scratch is intentionally an honest partial reconstruction. It does not
use volatile state, dead expressions, dummy references, inline assembly, or
layout-only gotos.

Current local score:

```txt
match=52.22% prefix=7/4206 target_insns=4206 candidate_insns=3983 refs=691/0/11
first_target=jne L3f7a
first_candidate=jne L3cea
```

The perk-funded shot charge at `0x0041595c..0x00415a08` tests Regression
Bullets positively and lays out its experience-spend arm before the
Ammunition Within damage fallback. The earlier equivalent reconstruction
inverted that outer test, so VC6 emitted the fallback first and tail-merged
the two branch-local float-to-int conversions. Restoring the native
positive-condition nesting recovers both `__ftol` calls, both experience
stores, and the native call order without artificial control flow. It adds
three candidate instructions, improves reference agreement from `685/0/13`
to `691/0/11`, and raises the whole-function score from `51.99%` to `52.22%`
while preserving the exact `0x48` frame.

The muzzle-effect direction lifetimes are now pinned across the normal weapon
dispatcher. Shrinkifier, Pistol, Assault Rifle, and SMG store each wide cosine
or sine result into the retained direction component and immediately multiply
that same x87 value by `25.0f` at `0x00415f54..0x004160a3`,
`0x00416138..0x0041616b`, and `0x0041676b..0x0041679a`. Interleaving those
ordinary component assignments recovers the native stores and prevents VC6
from collapsing the adjacent Shrinkifier/Pistol projectile and first-sprite
calls. Jackhammer at `0x004163df..0x00416406` and Rocket Minigun at
`0x00417141..0x00417168` do not retain a direction vector at all; writing
their single-use scaled trig results directly removes four unsupported local
stores. Together these changes add the missing direct projectile callsite,
recover the native first-sprite duplication, preserve the exact `0x48` frame,
improve reference agreement from `681/0/14` to `685/0/13`, and raise the
whole-function score from `51.77%` to `51.99%`.

The auto-target aim approach at `0x004156ca..0x004156d4` multiplies the
target distance by `6.0f` before applying `frame_dt`. Keeping that ordinary
source grouping explicit as `(scalar * 6.0f) * frame_dt` preserves the native
constant/reference order. It leaves the instruction count and whole-function
score unchanged while improving reference agreement from `679/0/16` to
`681/0/14`.

The native function keeps two related addresses live for essentially the
entire frame: `EDI` is the selected `player_state_t`, while `ESI` is the
address of its adjacent `pos_x`/`pos_y` pair. The earlier flattened scratch
re-derived those fields from `player` at each use, so VC6 assigned the two
bases to the opposite registers and repeatedly lost the native value lifetime.
Materializing one ordinary `float *player_pos = &player->pos_x` alias and using
it for coordinate reads, writes, and vector arguments recovers that evidenced
source shape. It adds 73 native-shaped candidate instructions, raises the
whole-function score from `39.13%` to `49.05%`, and improves reference
agreement from `594/0/32` to `667/0/16` without changing behavior or the exact
`0x48` frame. The remaining first mismatch is local scheduling around the
previous-position copy, not a missing simulation path.

The native weapon dispatch retains 33 direct `projectile_spawn` callsites and
four `fx_spawn_secondary_projectile` callsites. The earlier candidate emitted
only 26 and three: reusing one function-wide position temporary let VC6 merge
otherwise distinct one-shot weapon tails. Native repeatedly materializes the
same two-float physical stack slot in those branches while still retaining
their separate calls, which is evidence for short-lived source values whose
storage was coalesced after their lifetimes ended. Giving every simple direct
or secondary weapon arm its own scoped `spawn_pos` recovers that value shape
without growing the exact `0x48` frame. It raises the candidate to 32 direct
and all four secondary callsites, adds 45 native-shaped instructions, improves
reference agreement from `667/0/16` to `677/0/16`, and raises the score from
`49.05%` to `51.54%`.

The sole remaining direct-projectile collapse is the adjacent Shrinkifier and
Pistol pair. Native duplicates their projectile and first-sprite prefixes but
shares only the second-sprite tail at `0x0041600e`; the calibrated compiler
still merges the complete identical pair. The candidate therefore retains 24
sprite calls against 25 native, as well as two movement-avoidance calls against
three. Natural scoped movement values grow the frame to `0x4c`, while alternate
existing temporaries regress the proven body. Those residuals are left honest
rather than adding layout-only control flow or artificial dependencies.

The muzzle-flash decay at `0x00413842..0x0041384e` takes the address of
`player+0x2fc`, spills it to `[esp+0x24]`, and updates through that pointer.
The final clamp reloads the same pointer at `0x00417611`. Retaining an ordinary
source alias for this long-lived field adds four native-shaped candidate
instructions and one aligned reference, raising the match from `51.54%` to
`51.71%` without changing the exact `0x48` frame. A C++ reference compiled
identically, so the less ornate pointer spelling is retained.

The final bounds block uses the long-lived `ESI` position pointer for X but
tests Y as `player+0x18` through `EDI` at `0x004175ed`, then advances `EDI` to
that field for the remaining stores. Expressing the Y clamps through the
player record rather than the position alias recovers that source distinction
and raises the combined score to `51.73%`. A short-lived Y pointer compiles
identically; the direct field spelling remains the simplest plausible source.

The low-health direction at `0x004137b5..0x004137df` applies the `-6.0f`
scale to each wide `fcos`/`fsin` result before its first float store. Keeping
each trig call and scale in one ordinary assignment removes two premature
candidate stores, aligns one additional reference, and raises the current
score from `51.73%` to `51.77%`. An inlined vector `operator+=` for the
subsequent translation compiles identically, so the direct component adds are
retained as the simpler equivalent source.

Two stronger-looking alternatives were measured and rejected. Copying the
entry position as one aggregate lowers the score to `51.41%` and loses two
reference alignments. Giving Shrinkifier and Pistol separate scoped first-
sprite position/velocity values does preserve both native callsites, but grows
the frame to `0x50` and regresses the whole function to `50.87%`; the current
honest shared-local residual is kept instead.

The native reload preload gate at `0x00415037..0x00415069` first tests
`reload_timer - frame_dt < 0`, then tests `reload_timer > 0`. It never reads
the adjacent reload-active byte. Using the strict positive bound in the
scratch recovers the native second comparison and raises the whole-function
score from `39.10%` to `39.13%`. Both ports likewise key the preload only from
the positive timer crossing, including when a stale reload-active byte is
clear.

Angry Reloader writes the bonus-spawn guard to one at `0x00415132`, emits its
Plasma Minigun ring, and writes zero at `0x004151ce` before playing the impact
sound. The second store is unconditional; it does not restore the incoming
guard. Both ports now preserve that literal transition, with the Zig regression
starting from a set guard so a restore cannot pass accidentally.

The low-health pulse at `0x00413795..0x00413830` constructs its blood offset
in explicit vector phases: evaluate the heading-relative cosine and sine,
scale both components by `-6.0`, then translate them by the player's position.
It reloads `aim_heading` for the second trigonometric expression and only
captures the value used by the three effect calls after the translation.
Representing those natural value lifetimes recovers eight candidate
instructions and six additional reference matches, raising the whole-function
score from `38.72%` to `39.10%`. A temporary aggregate/constructor form grew
the stack frame, while combining scale and translation let VC6 reassociate the
arithmetic; neither reflects the observed native staging and both scored lower.

The native entry copies the adjacent `ui_mouse_x`/`ui_mouse_y` pair into the
selected two-float aim-screen slot with two integer moves. Representing both
pairs as the already-recovered local vector aggregate preserves that source
shape without bit-casting the individual floats merely to steer codegen.

Live disassembly also shows each early perk timer testing the perk count and
branching a zero result to its reset store, leaving the active update as the
fallthrough: Man Bomb at `0x004138bf`, Living Fortress at `0x004139c3`, Fire
Cough at `0x00413a0b`, and Hot Tempered at `0x00413c8a`. Restoring that natural
active-first source order changes no gameplay semantics, but recovers the
native `ebx`/`esi`/`edi` prologue through seven normalized instructions and
improves both whole-function alignment and reference recovery.

Live Binary Ninja shows the movement dispatcher at
`0x00413f19..0x00414f3e` laying out player-controlled modes first and branching
both demo mode and control mode `5` to the shared autoplay arm at
`0x00414c7f`. The earlier scratch put the demo arm first and left control mode
`5` stationary. Restoring the native condition and block order recovers the
computer-controlled movement behavior and raises the whole-function match from
`29.02%` to `37.79%`.

The same evidence revealed two rewrite-runtime parity defects. Aim scheme `5`
participates in the auto-target scan but does not select autoplay movement;
only demo mode or movement mode `5` does. The rewrite previously coupled
computer aim to computer movement. Also, the no-live-target arm at
`0x00414c7f` derives a tangential heading from the vector away from `(512,
512)`, so it orbits the arena rather than returning to center. The local input
interpreter now preserves the configured movement mode for computer aim and
reproduces that no-target orbit for computer movement.

The Zig rewrite had retained both defects independently in its local-input and
movement-runtime layers. It now routes autoplay only for demo mode or movement
mode `5`, preserves the configured movement vector when only aim scheme `5` is
selected, uses the native no-target tangent, and applies the zero deadzone used
by demo and point-click movement. Active port regressions cover each dispatcher
edge rather than relying on dormant module-local tests.

The firing dispatcher now follows the same native branch layout: an active Fire
Bullets timer falls through to the replacement path at `0x00415d13`, while an
inactive timer branches to the normal weapon cases at `0x00415eb8`. Man Bomb's
even and odd projectile arms each evaluate their randomized angle before
tail-merging at the common spawn, reproducing both native RNG call sites. The
Ammunition Within damage choice likewise converges on the single native
`player_take_damage` call instead of emitting one call per damage value.

Five native friendly-fire owner selections at `0x004138ea`, `0x00413a36`,
`0x00413cb5`, `0x0041512c`, and `0x00415be8` leave the enabled calculation
(`-1 - render_overlay_player_index`) in the fallthrough and branch to the
disabled sentinel (`-100`). The scratch now preserves that repeated natural
source order. The spread-damping gate at `0x00413d66` similarly leaves its
positive subtract-and-clamp arm in the fallthrough and branches to the
add-and-clamp arm. These source-level reversals recover six native references
without changing the instruction count or stack frame.

The spread-damping block is also active simulation state, not inert rendering
glue. Live instructions `0x00413d66..0x00413dcf` round the positive-gate
subtraction and the non-positive `frame_dt * 0.8f` recovery path at x87 PC=24,
then clamp the shared scalar to `[0.3, 1.0]`. The sole caller at `0x0040ad74`
loops `player_update` over every configured player, so the global advances once
for each live player. The Zig runtime previously declared both globals without
advancing them; its per-player perk phase now performs the native update after
Hot Tempered, matching both arithmetic staging and call cadence.

The two alternating projectile rings now also reproduce their native argument
selection. Man Bomb at `0x00413917` falls through on odd indices to the Ion
Rifle arm and branches on even indices to Ion Minigun, keeping the two native
random-angle evaluations. Hot Tempered at `0x00413ce1` selects Plasma Rifle or
Plasma Minigun directly in the call argument, which makes VC6 emit the native
`push owner; test parity; push type; shared call` sequence instead of reducing
a temporary projectile type arithmetically. Together with the owner and spread
ordering, this raises the whole-function score from `38.19%` to `38.72%`.

Live Binary Ninja isolates the native demo movement phase at
`0x00414c7f..0x00414f3e`. With no live target it derives an orbiting heading
from the vector away from `(512, 512)`. With a live target it pursues that
target while the player is within 300 units of center, otherwise steering back
toward center. Both cases reuse the normal heading approach, Long Distance
Runner acceleration, minigun speed cap, movement scaling, spawn avoidance, and
move-phase update. The recovered control flow places this as the demo arm of
the movement dispatch, so it joins the shared post-movement path without a
redundant demo-mode test.

This phase adds a net 164 candidate instructions against 186 native
instructions, closes the whole-function instruction gap from 591 to 427, and
raises the similarity ratio from `25.2142%` to `27.95%`. The Python demo driver
already implements the same orbit/pursuit/center-return policy, so no parity
port change is needed.

Live Binary Ninja isolates the native Fire Bullets path at
`0x00415d13..0x00415eb3`. The recovered source plays both dedicated shot
sounds, uses the fallback cooldown and muzzle-flash increment only when the
equipped weapon has one pellet, emits `pellet_count` type-`0x2d` projectiles
with `(rand() % 200 - 100) * 0.0015`, skips ammo consumption, spawns the gray
muzzle sprite, and adds the fallback spread term times `1.3` only without
Sharpshooter. It also corrects the normal path's first weapon heat increment:
native adds it to `muzzle_flash_alpha` (`player+0x2fc`), not `spread_heat`.

The new Fire Bullets block is 101 candidate instructions against 111 native
instructions and closes the whole-function instruction gap from 693 to 591.
The global similarity ratio nevertheless falls from `25.6510%` because the
corrected long-lived muzzle field and new branch perturb whole-function MSVC
register allocation and grow the candidate frame from `0x4c` to `0x54` while
native remains `0x48`. This is retained as substantive source recovery, not
represented as a matching-score improvement.

The accepted loop-family source follows the native weapon-case order and
restores 778 candidate instructions. Live Binary Ninja confirms the native
spread constants (`0.0013`, `0.004`, `0.002`, and `0.0026`), the Gauss/Ion
speed base of `1.4`, and the swarmer angular step of pi/3. The remaining
whole-function alignment delta comes from incomplete local-slot coalescing and
control paths. No register constraints or artificial padding are used.

## Port parity: Survival fire latch

Live instructions `0x0041590e..0x0041594f` first require either the normal or
reload-perk fire-ready byte, then require the configured fire key or auto-fire,
and only then write `1` to `survival_reward_fire_seen` at `0x00486fe4`. The
write precedes the Regression Bullets / Ammunition Within charge and actual
weapon dispatch. Both ports previously latched raw held fire during cooldown;
the weapon gate now owns the write, and replay input preprocessing no longer
manufactures it.

## Port parity: slot-zero perk ownership

Live Binary Ninja identifies 16 calls from `player_update` to the exact
`perk_count_get` helper, which always reads player slot 0. They cover Man Bomb,
Living Fortress, Fire Cough, Hot Tempered, Sharpshooter, Anxious Loader,
Stationary Reloader, Angry Reloader, Alternate Weapon, Regression Bullets, and
Ammunition Within. The recovered source also directly reads slot 0 for Long
Distance Runner, Fastshot, and the firing-path Sharpshooter check.

Both ports now select player 0 as the perk source for these phases when
`preserve_bugs` is enabled, while continuing to mutate the actual overlay
player's movement, timers, health, weapon, and projectile ownership. Corrected
mode retains intuitive per-player perk ownership. Focused co-op regressions
cover movement, a timed perk, and firing cooldown policy in both runtimes.
