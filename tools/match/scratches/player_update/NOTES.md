# `player_update` WIP

Native target: `crimsonland.exe` at `0x004136b0` (16,257 bytes).

This is the central per-player simulation routine. Live Binary Ninja evidence
and the existing parity port agree on the recovered opening phases:

- console short-circuit and per-player mouse/aim capture;
- previous-position capture and the dead-player timer path;
- speed-bonus application and the low-health blood/SFX pulse;
- muzzle-flash and weapon cooldown decay;
- Man Bomb's alternating eight-projectile ring; and
- Living Fortress timer accumulation and 30-second clamp;
- Fire Cough's randomized fire-bullet shot and sprite flash;
- Hot Tempered's alternating plasma ring; and
- the shared spread-damping scalar update.

Known missing work:

- movement/control-scheme dispatch and aim updates;
- reload and alternate-weapon handling;
- the full inlined weapon-fire dispatcher and final position clamps.

This scratch is intentionally an honest partial reconstruction. It does not
use volatile state, dead expressions, dummy references, inline assembly, or
layout-only gotos.

Current local score:

```txt
match=7.98% prefix=1/4206 target_insns=4206 candidate_insns=457 refs=71/0/10
first_target=sub esp, 0x48
first_candidate=sub esp, 0x40
```

The candidate's natural `0x40`-byte partial frame is already close to the
native `0x48` frame. The remaining eight bytes are expected to emerge from
the movement/reload locals; no artificial padding is used.
