# Behavior-preserving optimizations

These diffs change generated copies, leaving `decomp/` as the matching source
of truth. They apply to the verifier and game under both bug policies. Unlike
`patches/`, they must preserve all gameplay state and random-number draws.

`survival-spawn-batch.patch` resumes allocation from the previous slot within
Survival's wave loop. Only this batch has the guarantee that no occupied slot
becomes free. The cursor is local to `survival_update`; other allocator callers
search from zero. Full-pool attempts retain logging and overflow-slot writes.
See [original bug 37](../../docs/rewrite/original-bugs.md#37-survival-spawning-grows-without-bound-after-fifteen-minutes)
and the [profile](../../docs/verification/survival-spawn-profile.md).

Run `uv run python crimson-core/checks/spawn_batch.py` to compare 640 batches
against the same recovered bodies without optimization. To also confirm the
original game's late-time spawn counts through Unicorn:

```sh
uv run python crimson-core/checks/spawn_batch.py \
  --exe game_bins/crimsonland/1.9.93-gog/crimsonland.exe
```

CI runs both checks.

## Existing Python optimizations and core transfers

The [survey](../../docs/verification/optimization-survey.md) inventories the
previous Python performance changes, their invariants, and measured transfer
results. Keep Python implementations in their domain modules; this directory
holds only diffs to generated recovered C/C++. Compiler/ABI repairs stay in
`abi/`, runtime seams in `seams/`, and original gameplay bug fixes in `patches/`.

| Optimization | Python implementation | Core disposition |
| --- | --- | --- |
| Plaguebearer culling | `creatures/runtime.py` | `plaguebearer-culling.patch` |
| Phase-seed orbit direction cache | `creatures/ai.py` | `orbit-direction-cache.patch` |
| Ordered spatial hash, AoE/flame sharing | `creatures/spatial_hash.py`, `creatures/damage.py`, projectiles/particles | Potential later transfer; preserve ordering and mid-pass mutation visibility |
| Collision axis culling | `collision_math.py` | Direct transfer regressed; retain Python until a better measured algorithm exists |
| Size-margin LRU, integer masks, direct float packing/rounding | `collision_math.py`, creature hot paths, `math_parity.py` | Python overhead savings; native code already performs cheap arithmetic/bit operations |
| Empty projectile guards, target-distance reuse | Projectile runtimes, `creatures/ai.py` | Avoid Python work; any core transfer needs separate profiling and lifecycle audit |
| Raylib value construction and pan cache | `grim/raylib_api.py`, `grim/audio_math.py` | Python engine bindings; no verifier counterpart |

### Plaguebearer

Skip the update caller's infection search for a strong uninfected origin, whose
health cannot meet the native strict `< 150` infection gate. This skip is at the
caller because it ignores the returned slot; the function's index return remains
unchanged. Its private distance helper rejects axes at/outside 45 before PC24
squares/sqrt. The first active slot still wins, including corpses and the origin
itself; do not substitute nearest-neighbor or live-collision semantics.

### Orbit directions

Cache wide cosine/sine for the immutable phase seed. Allocation masks seeds with
`0x17f`, and splitting with `0xff`, so 384 entries suffice. Original phase spills
and every multiply remain unchanged. The patch explicitly uses `portable_mul32`
to preserve the wide cached value into the first PC24 multiply.
The cache contains derived constants only: it survives reset/seek without being
serialized or changing snapshots. It uses 9 KiB on the measured ABI.

Run `uv run python crimson-core/checks/creature_optimizations.py` to compare
Plaguebearer pool bytes and return values, strict-radius edges, strong-origin
skipping, all 384 orbit seeds, wide trig products and repeated cache reuse.
CI also runs the whole Python/native/WASM and game/verifier agreement gates.
