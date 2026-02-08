# RNG Divergence Root Cause Analysis

## Summary

The RNG divergence between the native Crimsonland and the Python rewrite is caused by a **cascade** originating from **floating-point precision differences** in creature movement calculations, which eventually flip a borderline projectile collision from miss to hit, generating extra presentation RNG draws that permanently desynchronize the shared RNG stream.

## Chain of Events

### 1. Floating-point precision drift (ticks 0–3452)

The native creature AI code uses **x87 FPU instructions** (`fsin`, `fcos`, `fpatan`) which compute at **80-bit extended precision** and store results into **32-bit float** fields. The Python rewrite uses `math.sin`/`math.cos`/`math.atan2` which compute at **64-bit double precision** and store in 64-bit Python floats.

Native `creature_update_all` (0x00426220), velocity calculation:

```c
fVar11 = (float10)(&creature_pool)[...].heading - (float10)1.5707964;
fVar12 = (float10)fcos(fVar11);   // 80-bit precision
vel_x = (float)(fVar12 * frame_dt * local_70 * move_speed * 30.0);  // truncated to 32-bit
```

The precision mismatch causes creature positions to drift:

| Tick | Max creature position drift |
|------|-----------------------------|
| 100  | 0.000356 units              |
| 500  | 0.001711 units              |
| 2635 | 0.569373 units              |
| 3453 | 0.541041 units              |

### 2. Borderline collision flip (tick 3453)

At tick 3453, a **Fire Bullets** projectile (proj=3, type_id=6) traverses creature 19 during substep collision checks. In the rewrite, the collision check at substep 57 produces:

- `dist = 11.374535`, `threshold = 10.285715`
- `margin = +0.088821` → **MISS**

Creature 19's position differs by 0.117 units between native and rewrite (`x_delta = -0.116419, y_delta = -0.010888`). In the native, the creature is close enough that this same collision check results in a **HIT**.

- **Native: 5 projectile-creature hits** at tick 3453
- **Rewrite: 4 projectile-creature hits** (missing the substep-57 hit on creature 19)

### 3. Presentation RNG shortfall (tick 3453)

The extra hit in the native generates additional **presentation effects** that consume the shared RNG:

- 2 extra `effect_spawn_blood_splatter` calls → 20 rand draws
- 1 extra `queue_large_hit_decal_streak` → ~30 rand draws
- additional `fx_queue_add_random` calls → ~36 rand draws

| Metric | Native | Rewrite |
|--------|--------|---------|
| Total rand calls | 353 | 268 |
| Prefix match | — | first 268 values match native exactly |
| Shortfall | — | 85 rand draws from extra hit's presentation |

### 4. RNG state permanently desynchronized

After tick 3453, the RNG internal state diverges (native output=269, rewrite output=7125). All subsequent ticks see different random values.

### 5. Gameplay divergence at tick 3504

51 ticks later, the desynchronized RNG causes a Fire Bullets projectile in the rewrite to hit and kill creature 46 (type_id=2, xp=35) that the native doesn't kill. This produces the observed field divergence:

- `players[0].experience`: native=2263, rewrite=2298, **delta=35**

## Root Cause

**x87 80-bit → 32-bit float vs Python 64-bit double precision** in creature movement trig functions (`fsin`/`fcos`/`fpatan`). The intermediate precision mismatch slowly drifts creature positions until a borderline collision changes outcome, which then desynchronizes the shared gameplay+presentation RNG stream.

## Additional Notes

- The RNG itself is implemented correctly (MSVC CRT `rand()`, verified bit-exact).
- All rand() values match perfectly for ticks 0–3452, confirmed by comparing the internal 32-bit state at each checkpoint tick.
- `SpriteEffectPool.spawn()` correctly ports `fx_spawn_sprite` (including the 1 rand draw for rotation), but its rand calls bypass the focus trace's monkey-patching because the rand reference is captured at init time as a bound method. This produced false-positive `delta=-2` call count mismatches at ticks where the player fires (e.g. tick 535). The actual RNG state was correct at those ticks.
- The `fx_spawn_sprite` muzzle flash draws (2 per weapon fire) are not the source of divergence.

## Methodology

1. Replayed the sim tick-by-tick, comparing the CRT rand output value `(state >> 16) & 0x7FFF` at each checkpoint tick against the capture's `rng_state` field. Found first state mismatch at tick 3453.
2. Ran focus trace at tick 3453: confirmed 268 rewrite rand calls with prefix_match=268 against native's 353 calls.
3. Mapped the 85 missing native tail calls to `fx_spawn_sprite` addresses (`0x0042ebc0`–`0x0042ec44` for blood splatters, `0x0042176f`/`0x0042184c` for fire bullets decals) via Ghidra decompilation.
4. Identified the near-miss at substep 57 creature 19 (margin=+0.089) and the creature position drift (0.117 units) that flips it to a hit in the native.
5. Traced the position drift back to x87 `fsin`/`fcos`/`fpatan` vs Python `math.sin`/`math.cos`/`math.atan2` precision differences in `creature_update_all`.
