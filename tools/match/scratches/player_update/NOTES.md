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

- the shared demo/AI auto-target movement path after acquisition;
- exact local lifetimes/register allocation around the recovered control paths.

This scratch is intentionally an honest partial reconstruction. It does not
use volatile state, dead expressions, dummy references, inline assembly, or
layout-only gotos.

Current local score:

```txt
match=25.2142% prefix=1/4206 target_insns=4206 candidate_insns=3615 refs=292/0/50
first_target=sub esp, 0x48
first_candidate=sub esp, 0x54
```

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
