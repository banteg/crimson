---
tags:
  - verification
  - performance
---

# Crowded combat and perk-menu stalls

The clearest combat stall was a **miss**. With Barrel Greaser, one Gauss Shotgun volley took 41 ms to pass a packed crowd in the Python port. Moving the same crowd farther from the trajectory reduced the update to 1.2 ms. The largest one-off stall was opening a nearly exhausted co-op perk menu.

| Operation | Python median | Recovered WASM median |
| --- | ---: | ---: |
| Gauss Shotgun misses 384 nearby creatures | 40.7 ms | 0.137 ms |
| Same volley, same creatures moved 240 units farther away | 1.2 ms | 0.137 ms |
| One Splitter Gun round, 16 zombies spaced 3 units apart | 8.6 ms | 0.064 ms |
| Same shot and zombies, spaced 12 units apart | 0.9 ms | 0.007 ms |
| RTX ion lights, contact glows and artwork target selection, eight impacts alongside 384 creatures | 10.6 ms | — |
| Same ion impacts, same creatures moved out of reach | 2.7 ms | — |
| Open co-op perk menu with 25 single-pick perks owned on a fresh profile | 115 ms | 1.49 ms |
| Same menu, no perks owned | 0.04 ms | <0.001 ms |
| Recorded Survival tick 34680, Final Revenge | 5.5 ms | 0.047 ms |

The Final Revenge row measures a complete headless tick from a checked-in recording. The other rows isolate individual operations in controlled states. The RTX row measures CPU preparation before draw submission. WASM timings are for the headless verifier in Node. Neither measures GPU or browser frame time.

## Gauss Shotgun misses repeatedly test the same crowd

The six slugs from a single trigger pull made **288 radius queries** in their first tick. The original 1.9.93 executable searched all 384 slots on each miss, for **110,592 slot visits**. Python uses 64-unit spatial buckets. A query with radius 1 still collects its own bucket and eight neighbors to allow for a creature's size, then sorts the candidate slots and checks them individually.

With 96 targets just beside the flight path, Python made 15,168 exact radius checks and took 11.4 ms. With 384 there, it made **60,672 checks for zero hits**. Shifting the 384 targets clear of those buckets preserved all six projectiles and reduced exact checks to zero. A narrower candidate search would have to preserve the first hit in slot order and see creatures moved or spawned earlier in the same tick. The relevant paths are `src/crimson/creatures/spatial_hash.py` and `src/crimson/projectiles/runtime/projectile_pool.py`.

## RTX ranks the same ion arc targets twice per frame

One Ion Shotgun fires eight pellets. Put their impacts together in a crowd and the Python renderer selects the best four targets per impact for lights, then repeats that selection for contact glows with the same view center. Slot zero is excluded. With 384 occupied slots this ran the ranking function **6,128 times** (`8 × 383 × 2`) to emit 32 contact glows. The artwork also walks the targets with its own per-cell cap.

A temporary cache shared the light and glow results for just one frame. Timing those two consumers alone went from **8.6 to 4.5 ms** with identical light and glow lists. The native client's light and glow collectors also call the same four-target selector separately. The measured saving is for Python. The selectors are in `src/crimson/render/rtx/material_lights.py` and `crimson-core/game/rtx_lights.cpp`.

## One Splitter Gun round fills the projectile pool

No splitter spiders are needed. On contact, a round emits two more rounds, including on a still-collidable corpse. The projectile loop walks forward through live slots, so children placed in later slots can split again **in the same update**. The 96-slot allocator overwrites the last slot once full.

With 16 ordinary 100 HP zombies packed three units apart, one round registered **75 impacts, 150 child spawns and 10 deaths in one tick**. The original executable attempted 569 effect spawns and ended with all 96 projectile slots active. At 12-unit spacing Python registered six impacts and ended with 13 active projectiles. Deferring fragments by a tick would change which targets the weapon hits. See `projectile_update` (`0x00420b90`) and `projectile_spawn` (`0x00420440`).

## The co-op perk menu rolls 60,173 candidates for seven identical offers

On a two-player Survival profile with no quest unlocks, there are 25 eligible single-pick perks and one repeatable offer, Instant Winner. The original generator fills seven slots even when the menu shows fewer. After offering Instant Winner once, it rejects duplicates until the current slot has exceeded 10,000 attempts.

With RNG seed 97 and 21 of the 25 perks owned as in the reproducer, the generator made **44,955 RNG draws** and took 32 ms in Python. With all 25 owned, it made **60,173 candidate selections and 134,131 RNG draws** to return seven copies of Instant Winner. The fresh menu took 18 draws. The original executable returned the same seven IDs and ended at the same RNG state in all three cases. A shortcut that only fills the visible rows would change subsequent spawns and drops. See `perks_generate_choices` (`0x004045a0`) and `src/crimson/perks/selection.py`.

## One blast can process an entire splitter family

In the recorded Survival run, Final Revenge generated **122 death events in tick 34680**. The profile counted 47 split bursts and 384 effect spawns that tick. This was a 5.5 ms Python tick. The recovered WASM verifier took 0.047 ms, compared with 0.018 ms for the preceding 31 ticks at the median.

A controlled Nuke isolates the cause. Put one full-health, size-80 stock splitter near the blast center in slot zero with the later slots free. Each death allocates its children ahead of the scan, still inside the blast. The original executable processed **127 deaths, 126 child allocations and 512 effect-spawn calls** during that pickup. Three nearby roots produced **381 deaths and 1,520 effect-spawn calls**. The Python pickup alone took 0.09 ms with no roots, 3.6 ms with one and 15.9 ms with three. These runs had no Freeze and no ice shards. The sequence depends on which slots are free when each creature dies. It is visible in `bonus_apply` (`0x00409890`) and `creature_handle_death` (`0x0041e910`).

## Reproduce

```sh
uv run python -m scripts.bench_gameplay_bursts --replay
```

Measured on an Apple M1 Pro at commit `b5a1bb439`, using Python 3.13.16 and Node 26.12.1. The Python benchmark times 13 repetitions after one warm-up, with setup and state restoration outside the timer. It collects call counts on a separate repetition. The recorded case uses `tests/fixtures/replays/survival-238852.crd` and zero-based tick numbers.

Original-game counts came from running the GOG 1.9.93 EXE's functions under the [native oracle](differential-testing/native-oracle.md). For the controlled WASM rows, the verifier objects were relinked with the projectile and perk routines exported, then timed over 130 warm calls with the starting state restored before each call. For the recorded row, the unmodified verifier replayed the full input stream 12 times after a warm-up. Each pass ended at the same snapshot hash.
