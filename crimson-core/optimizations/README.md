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

`survival-spawn-overflow.patch` skips a full pool's rewrites. Once the batch's
cursor reaches the overflow slot, every later attempt writes that slot whole,
and the batch's last attempt rewrites every field but `flags`, where a type 3
keeps 0x80. So the attempts before the last only take their random draws (the
side, the position and the spawn body's, stepped through the host's
`crt_rand_stream` through `host/crt_rand.h`) and set 0x80 for a type 3; the last
runs as recorded. The
batch's attempt count follows from the cooldown and the elapsed time alone.
Verbose logging, which writes once per attempt, keeps every attempt.
A pass's inner attempts skip in one call, and most of them without stepping
the stream draw by draw. The stream n draws on is one multiply and one add
from the attempt's first state, and outside the 25,000 to 42,000 experience
band an attempt takes 15 draws unless it rolls a tinted variant or a giant
(2.2% of attempts). The skip reads those three rolls and the type's two at
their places, checks them, and jumps 15 draws; an attempt that fails the check
steps draw by draw as before.
The fixed draw positions deliberately couple the fast path to the spawn body's
draw order and its draw-by-draw skip. Keep all three in sync; `spawn_batch.py`
compares them against the unoptimized recovered body. Both stepping and jumping
use the generator defined in `host/crt_rand.h`.
Python's Survival wave also skips intermediate phantom writes, while retaining
all tagged RNG draws. Every extra attempt has a later main spawn, and a main
attempt is transient only while its updated cooldown stays negative; no
separate attempt count is needed. Standalone spawns always write normally.
`spawn_batch.py` also compares three consecutive `survival_update` calls with
unoptimized ones across elapsed times, frame times, player counts, cooldowns,
experience bands, pool fill and verbose logging.

`headless-effects.patch` skips the effects' vertex math where nothing draws.
`effects_render` only draws: per effect it builds a rotation matrix and a packed
color and submits them, and Grim drops submits while `grim_render_disabled` is
set. The verifier never draws (`PORTABLE_DRAWING`, host/hooks.h), and the game
draws nothing on a replay's undrawn ticks: the preparing pass, seeks, and all
but a frame's last tick at high speed. The batches' state calls stay, since
Grim keeps their blend modes and texture for the frames that do draw. Other
render passes write gameplay state (`creature_render_type` frees corpse slots,
`projectile_render` retires projectiles, `bonus_render` picks bonuses up), so
they run everywhere.

`headless-creatures.patch` and `headless-projectiles.patch` do the same for
those two passes, keeping the one write each makes. `creature_render_type`'s
body loop frees a corpse once its death timer passes -10, and its spawner's
slot with it; `projectile_render`'s trail loop retires an active projectile of
type 0. Where nothing draws, the body loop only frees, the trail loop only
retires, and the loops that only draw (the creatures' shadows, hit flashes,
marks and freeze overlay; the plasma trails, the projectiles' sprites, ion
arcs, glow and bullet heads, the Plague Spreader's cloud and the secondary
projectiles) leave at
once. `creature_render_all`'s early return still decides whether the corpses
are freed at all. The Fire Bullets glow and the bullet heads leave on lines
the game's fixes for original bugs 34 and 28 do not quote, so those two
patches apply unchanged, and the glow was the only reader of the entry the
sprite loop ends on.

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
