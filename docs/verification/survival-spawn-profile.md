---
tags:
  - verification
  - performance
---

# Late-game Survival spawn profile

[Original bug 37](../rewrite/original-bugs.md#37-survival-spawning-grows-without-bound-after-fifteen-minutes)
explains the spawn-rate escalation. The core's
[batch optimization](../../crimson-core/optimizations/survival-spawn-batch.patch) removes
redundant first-free searches while preserving that original behavior.

## Recording and baseline

Profiled on 2026-10-10, Apple M1 Pro, 32 GiB RAM.
[egornomic's Survival replay](https://crimson.land/play/?watch=209b0cdb6d9345e8c2dc4eaeac654e929338eecf07aaad28aaf9137dd9bc38d6)
contains 210,268 input ticks, 143,802,723 XP, 9,819 kills and 35:54.555 of game
time. The baseline is release 0.14.2, commit
`f8e743454598b1fc408b84c124943e2bb54ffb2f`. Its packaged browser WASM was
byte-identical to the deployed `/play/index.wasm` when profiled:
SHA-256 `d7b65d9a9fd77c93ee0244f8174c012480b61b205a4422735d1c15db3e7ca937`.
The replay file's SHA-256 is
`d6ad07f0702ff21ac829aca3d0d7deb05adac9c1f4107bcd715bf2110cee036a`;
the watch ID is a run identifier, not this file hash.

## Cost before optimization

Exact counters in a diagnostic build counted **219,862,950 Survival spawn
attempts**. The 384 usable creature slots were nearly continuously occupied
in the late game. The original's full-pool allocation scans all 384 slots,
then still runs the spawn body against overflow slot 384.

An initial Chrome/Metal measurement took **102.07 s** to prepare the whole
replay, including **101.41 s** in preparation frames. The instrumented build
took **105.78 s** wall time, 3.6% more. Its disjoint frame-work categories were:

| Work | Seconds |
| --- | ---: |
| Survival update and spawning | 54.53 |
| Other tick work | 33.87 |
| Creature update | 7.44 |
| Projectile update | 3.79 |
| Terrain baking and logging | 3.14 |
| Keyframe and terrain copies | 1.60 |
| Frame/UI overhead | 0.69 |

CPU sampling separately attributed 35.67 s of self time to the allocator,
9.25 s to Survival spawning and 6.49 s to RNG. Samples include some startup
and playback and must not be added to the timer table.

The pure zero-import WASM simulation took 49.36 s and 49.21 s in its two
uncontended warm repeats. Average tick time rose from 19.4 µs in minutes 0–5
to 693.9 µs in minutes 30–35. After minute 15 accounted for 90.3% of simulation
time. This is a separate execution path from the browser's wasm2c build;
its time is not an additive component of browser preparation.

## Before and after

The repeated baseline and optimized browser builds used the same host, assets,
viewport, diagnostics and Metal GPU, measured sequentially without competing
profiling work:

| Browser preparation | Baseline | Optimized |
| --- | ---: | ---: |
| Wall time | 96.70 s | 62.03 s |
| Preparation frame work | 96.02 s | 61.47 s |
| Frame p99 | 104.1 ms | 82.6 ms |
| Largest frame | 237.3 ms | 172.0 ms |

Preparation was **35.9% shorter**. The earlier baseline was 102.07 s, so timing
varies between runs; this is one fresh before/after browser pair, not a confidence
interval. Late frames still exceed the nominal budget. The cursor removes pool
searches, but does not skip any of the roughly 220 million spawn bodies.

The paired zero-import WASM benchmark ran three times per build, reversing
order on the middle repetition. The two warm repeats were:

| Pure simulation | Baseline | Optimized |
| --- | ---: | ---: |
| Warm repeat 1 | 45.99 s | 26.55 s |
| Warm repeat 2 | 45.59 s | 26.44 s |
| Warm median | 45.79 s | 26.50 s |

Simulation was **42.1% shorter**. All six runs produced the same terminal
snapshot hash. The [measurement summary](../../crimson-core/results/survival-spawn-profile.json)
records each repetition, module/replay hashes, frame statistics and validation
coverage. The earlier 49.2 s baseline belongs to the initial profiling session;
the paired benchmark above is the before/after comparison.

## Python wave updates

Python has the same negative-interval loop and first-free pool scan. It now uses
the same local cursor, reset to zero on every update. For a saturated pool at
35:54.555, slot reads fall from 5,584 × 384 = 2,144,256 to 384 per update.
All 5,584 spawn bodies and 83,533 random draws still execute.

A bounded benchmark times only one saturated wave update, with one player,
16 ms delta, zero starting cooldown, stage 10, seed 97 and 143,802,723 XP.
World construction and state serialization are outside the timing window.
Each build ran four sequential repetitions without competing CPU work; the
table gives the median of the last three.

| Elapsed game time | Attempts | Python baseline | Python optimized |
| --- | ---: | ---: | ---: |
| 15:00 | 16 | 0.336 ms | 0.213 ms |
| 30:00 | 4,016 | 75.06 ms | 48.47 ms |
| 35:54.555 | 5,584 | 104.01 ms | 66.57 ms |

The late update is **36.0% shorter**. These are synthetic saturated-pool wave
measurements, not complete Python replay preparation. Before/after hashes of
the full usable pool, phantom, allocation/spawn counters, RNG state and
cooldown/stage match in every repetition. Python still pays for all spawn
initialization and float-parity calculations.

## Validation

- Python differential tests compare complete creature/phantom/spawn-slot state,
  counters, generations and tagged RNG traces against searches from zero, under
  both bug policies, empty/fragmented/full pools, co-op and later slot reuse.
  Six actual wave updates also match the original executable at the onset and
  two late-game times, including fragmented and saturated pools.
- The updated Python rewrite agrees with the native core on all 110 supported
  replay-gate streams (101 bot scenarios and nine recordings); the established
  unsupported fixture remains excluded.
- The original x86 executable, executed through Unicorn with its allocator
  and spawn body intact, reproduces 16 spawn attempts at 15:00, 32 at
  15:01.800, 4,016 at 30:00 and 5,584 at 35:54.555 for a 16 ms update,
  one player and a zero starting cooldown.
- The compiled differential harness compares 640 batches against the
  unoptimized recovered bodies. It covers empty, fragmented and full pools,
  all experience thresholds, 0–5,600 spawns per batch, dirty overflow fields,
  verbose logging and reuse of low slots after a later free. All pool bytes,
  RNG state, spawn counts and log counts match.
- Baseline and optimized core snapshots match all 36,343 fields at
  initialization and every tick of 101 existing streams plus this recording:
  508,609 ticks, including the overflow slot and RNG state.
- The optimized game module agrees with the optimized verifier at every tick
  of the reported replay, excluding the established presentation-only popup
  timers and weapon sound IDs. Browser preparation completes and rewinds
  into playback.
- The optimized native/WASM matrix passes all 101 scenarios, resets and
  rejection checks. Both bug policies retain their original rules.

## Reproduction

Run the Python wave benchmark in each checkout, using the same environment:

```sh
PYTHONPATH=.:src uv run python crimson-core/checks/profile_python_wave.py --out python-wave.json
CRIMSON_NATIVE_ORACLE=1 uv run pytest tests/native_oracle/test_spawn_full_pool.py
```

The baseline checkout can use the benchmark script from the optimized checkout.
Compare every snapshot hash as well as times; use the original executable under
`game_bins/` for native checks.

Run the bounded core batch check:

```sh
uv run python crimson-core/checks/spawn_batch.py \
  --exe game_bins/crimsonland/1.9.93-gog/crimsonland.exe
```

Omit `--exe` to run only the compiled batch comparison.

For the reported recording, download its `.crd` from
[the public run archive](https://crimson.land/runs/209b0cdb6d9345e8c2dc4eaeac654e929338eecf07aaad28aaf9137dd9bc38d6.crd),
check its hash, then convert it with `crimson-core/checks/replay.py`.
Build the baseline and optimized WASM cores in separate checkouts, and run:

```sh
uv run python crimson-core/checks/replay.py run.crd --out run.rsi
node crimson-core/checks/profile_replay.mjs run.rsi before.wasm after.wasm comparison.json --compare
node crimson-core/checks/profile_replay.mjs run.rsi before.wasm after.wasm timing.json
```

The profiler times 600-tick blocks, excluding snapshots, over three repetitions
per build and reverses execution order on the middle repetition. It requires
matching terminal snapshot hashes. `--compare` checks every field at every tick.
Avoid other CPU work while measuring.

Browser measurements use Chrome headless with ANGLE's actual Apple M1 Pro
Metal renderer, a 1280×800 viewport and the production asset packs. Both builds
use the same original SDL host, `-O2`, profiling function names and diagnostic
exports for watch progress. Timed work runs from the first preparing frame
through the completion/rewind frame; assets and launch are outside the window.
Snapshots are read after, outside each timed frame. CPU sampling runs throughout
preparation for both builds. Reported memory capacity is the inner game module's
reserved linear memory, excluding the outer Emscripten heap, GPU resources and RSS.

The original 28 ms preparation budget is checked only after each 64-tick chunk.
The optimization retains every spawn attempt and its random draws; remaining
spawn/RNG work and world presentation calculations still make late ticks costly.
Keyframe compression was a small fraction of the measured preparation time.
