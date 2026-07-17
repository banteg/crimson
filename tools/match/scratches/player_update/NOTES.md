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

This scratch is intentionally an honest partial reconstruction. It does not
use volatile state, dead expressions, dummy references, inline assembly, or
layout-only gotos.

Current local score:

```txt
match=37.79% prefix=2/4206 target_insns=4206 candidate_insns=3811 refs=574/0/36
first_target=push ebx
first_candidate=push ebp
```

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

The firing dispatcher now follows the same native branch layout: an active Fire
Bullets timer falls through to the replacement path at `0x00415d13`, while an
inactive timer branches to the normal weapon cases at `0x00415eb8`. Man Bomb's
even and odd projectile arms each evaluate their randomized angle before
tail-merging at the common spawn, reproducing both native RNG call sites. The
Ammunition Within damage choice likewise converges on the single native
`player_take_damage` call instead of emitting one call per damage value.

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
