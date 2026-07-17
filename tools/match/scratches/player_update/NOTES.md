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
- mouse, analog-stick, joystick-cursor, keyboard, POV, and smoothed auto-target
  aim updates;
- manual reload, Sharpshooter cooling, Anxious Loader, Stationary Reloader, and
  Angry Reloader's projectile ring; and
- movement-phase normalization, speed-bonus removal, terrain clamping, and the
  final muzzle-flash clamp.

Known missing work:

- the shared auto-target movement acquisition/re-entry path;
- alternate-weapon swapping and the full inlined weapon-fire dispatcher; and
- exact local lifetimes/register allocation around the recovered control paths.

This scratch is intentionally an honest partial reconstruction. It does not
use volatile state, dead expressions, dummy references, inline assembly, or
layout-only gotos.

Current local score:

```txt
match=16.21% prefix=1/4206 target_insns=4206 candidate_insns=1767 refs=156/0/47
first_target=sub esp, 0x48
first_candidate=sub esp, 0x44
```

The candidate's natural frame grew from `0x40` to `0x44` as recovered locals
and their lifetimes were introduced. The remaining four bytes are expected to
emerge from the missing fire/control source; no artificial padding is used.
