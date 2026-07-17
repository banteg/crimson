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
- the Fire Bullets branch;
- exact local lifetimes/register allocation around the recovered control paths.

This scratch is intentionally an honest partial reconstruction. It does not
use volatile state, dead expressions, dummy references, inline assembly, or
layout-only gotos.

Current local score:

```txt
match=25.6510% prefix=1/4206 target_insns=4206 candidate_insns=3513 refs=299/0/46
first_target=sub esp, 0x48
first_candidate=sub esp, 0x4c
```

The accepted loop-family source follows the native weapon-case order and
restores 778 candidate instructions. Live Binary Ninja confirms the native
spread constants (`0.0013`, `0.004`, `0.002`, and `0.0026`), the Gauss/Ion
speed base of `1.4`, and the swarmer angular step of pi/3. The candidate keeps
its natural `0x4c` frame; the four-byte excess and the remaining whole-function
alignment delta come from incomplete local-slot coalescing and control paths.
No register constraints or artificial padding are used.
