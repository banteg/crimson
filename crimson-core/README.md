# Crimson core

The recovered C/C++ gameplay from [`decomp/`](../decomp) built into one
deterministic simulation, as a native executable and an import-free WASM
module. It is being developed into the shared core of the shipped game and the
replay verifier, so live play, the web build and leaderboard verification run
the same module. Python stays the reference port for fast iteration; the
[Zig port](../crimson-zig) is frozen until this core takes over verification.

`decomp/` stays the matching source of truth. The core compiles generated
copies of 168 recovered translation units; everything it adds lives here.

## Status

- **Original rules:** whole runs agree with Python (`preserve_bugs=True`) on
  53 of 63 streams; see the [gate](#whole-run-gate) for the ten that remain.
- **Ranked rules** (`preserve_bugs=False`): not started. Python's documented
  fixes are to be applied in place behind a runtime policy flag, so RNG call
  order matches Python under both policies. See the [roadmap](ROADMAP.md).
- Native and WASM snapshots are bit-exact on 59 bot scenarios, including
  resets. Quest builders and gameplay math match the original executable.

## Scope

- One player at a fixed 60 Hz in Rush, Survival and all 50 Quests.
- Dual-action movement with mouse aim (a world point) or dual action pad aim
  (the stick's reach from the moved position), read from each tick's flags as
  Python does. Keyboard movement schemes, Typ-o, the tutorial and more players
  fail explicitly.
- Original rules only.

## Layout

| Path | Contents |
| --- | --- |
| [`build.py`](build.py), [`adapter.py`](adapter.py), [`data.py`](data.py) | Generate, adapt and compile the recovered sources; recreate the globals. |
| [`sources.json`](sources.json), [`provenance.json`](provenance.json), [`schema.json`](schema.json) | Selected bodies, pinned dependency hashes, snapshot fields. |
| [`host/`](host) | The host the recovered code runs in: API, input, timing, stubs, portable math. |
| [`checks/`](checks) | Native/WASM matrix, Python whole-run gate, original-executable oracles, Wasmtime probe. |
| [`results/`](results) | Checked-in results of those checks. |
| [`worker/`](worker) | Diagnostic Cloudflare Worker that runs the WASM module. |

## Build

Run from the repository root. Requires clang++, Zig **0.16.0**, Node.js and the
project's Python environment. Tested on macOS ARM64; CI runs Linux x86-64.
The transport assumes little-endian hosts.

```sh
uv run python crimson-core/build.py
uv run python crimson-core/build.py --target wasm
```

Outputs land in `crimson-core/build/{native,wasm}`. The build stops when a
pinned recovered source, header or the data-definition manifest changes; audit
the adapters before refreshing `provenance.json`.

## Checks

### Native/WASM matrix

```sh
node crimson-core/checks/matrix.mjs
```

An ordinary bot reads state, chooses inputs and perks, and never edits
simulation state. It writes 59 input-only `.rsi` streams to `build/fixtures`,
alternating mouse and pad aim. The matrix compares 36,343 named fields at
initialization and **every tick** between native and WASM, then checks A/B/A
reuse in both. It also probes rejection of bad input, commands and entitlement,
and that a large movement vector does not move faster than a unit one.

The [results](results/matrix.json) cover 95,205 ticks. All 50 quests run to an
outcome; the bot completes 1.1, 1.3 and 1.5. Coverage includes game over in
every mode, quest completion and failure, spawn stalls, reloads, perk menus,
ordered picks, several weapons, freeze, Reflex Boost and weapon power-ups, and
a settings case varying hardcore, retry scaling, detail, violence, friendly
fire and weapon-usage history. The snapshot is a diagnostic schema: pointers
become pool indices, and padding, static addresses, draw vertices and
presentation-only HUD slots are left out. It is not a save-state format.

A single stream can be replayed with
`node crimson-core/checks/compare.mjs <stream.rsi> <native core> <core.wasm>`.

### Whole-run gate

```sh
uv run python crimson-core/checks/gate.py --out crimson-core/results/gate.json
```

The gate feeds each bot stream and each supported recorded fixture to Python
and the native core. Per tick it compares the RNG state, kills, shots, pending
perks, bonus timers and the player's position, health, death timer, headings,
experience, level, ammo and weapon, floats as F32 bits, keeping the first
divergence. It compares the terminal tick and outcome, and the complete
`RunResult` after the last tick both stepped. Recorded fixtures were played
under the default rules, so under the original rules they may end early; the
gate stops at the core's terminal state and does not validate recorded scores.

The [baseline](results/gate.json) agrees on **53 of 63** streams, including the
four supported human fixtures (Quests 2.5, 2.10 and 4.10, and a Survival run).
The ten that differ:

- Rush (3 streams): every field agrees on every tick, but Python ends the run
  when the player dies, while native `gameplay_update_and_render` waits for the
  death animation as in the other modes, 48 ticks later.
- Quest 2.10: the double-XP timer differs by one tick on the terminal tick.
- Quest 1.5: Python draws one RNG value a tick early; results agree.
- Quests 4.10 and 5.6 (Python takes damage the core does not), Quest 5.4 (seven
  extra core draws), and late F32 drift in Quest 3.7 and `survival-evade-1337`.

These are to be reduced and decided against the original through Unicorn. The
gate exits nonzero until every stream agrees, so it is not in CI yet.

### Original executable

The oracles call the original code through Unicorn, using the ignored game
binary. Unicorn's JIT must run outside the command sandbox, as documented in
`tests/native_oracle/conftest.py`.

```sh
uv run python crimson-core/checks/builder_oracle.py \
  --exe game_bins/crimsonland/1.9.93-gog/crimsonland.exe \
  --out crimson-core/build/oracle.json
uv run python crimson-core/checks/math_oracle.py \
  --exe game_bins/crimsonland/1.9.93-gog/crimsonland.exe \
  --out crimson-core/build/math-oracle.json
```

- [Quest builders](results/builder-oracle.json): all spawn-table fields, entry
  counts and final RNG states for 50 builders × 32 seeds × normal/hardcore
  agree, 3,200 cases, native and WASM alike. Later quest-start difficulty
  adjustments are not covered.
- [Gameplay math](results/math-oracle.json): 7,877 cases against original x87
  instructions, covering Normalize (near-unit, `FLT_MIN` and every finite F32
  exponent range, separate and in-place destinations), CRT power and level
  thresholds, and movement trig products. The core has no mismatches. Python
  has three extreme vector discrepancies (six with alias modes) from rounding
  a subnormal result straight to F32 instead of to PC24 first.
These are bounded checks of selected seams, not whole-run equivalence. An
earlier one-off check stepped a sampled movement state through the original
code and established that the movement trig result is not spilled before its
first PC24 multiply; the adapter keeps that boundary.

### Same WASM from Python

```sh
uv run --with wasmtime==49.0.0 python crimson-core/checks/wasmtime_check.py \
  --out crimson-core/build/wasmtime.json
```

The [probe](results/wasmtime.json) loads the exact `core.wasm` used by Node and
the Worker in [wasmtime-py](https://bytecodealliance.github.io/wasmtime-py/),
compares the hash of every snapshot in all 59 scenarios and checks A/B/A resets
in one instance, without adding a project dependency. A rendered desktop client
still needs graphics and audio imports. The 9,995-tick Survival run takes about
**0.15 s** in a warmed Node WASM instance (simulation and input transfer,
without snapshots, initialization or bot decisions); linear memory stays at
**2.5 MiB** and the stripped module is about **357 KiB**.

### Worker

```sh
cd crimson-core/worker
WRANGLER_SEND_METRICS=false wrangler dev --local --ip 127.0.0.1 --port 8799
```

Then, from the repository root, `node crimson-core/worker/worker_check.mjs`
compares every stream's final-state hash with native and WASM, including reuse
of one instance across requests. Nothing is deployed. The endpoint takes the
private transport, capped at 4 MiB, 60,000 ticks and 16 commands per tick, and
always reinitializes before the next request. Initialization through copying
the final snapshot is synchronous, so requests cannot interleave simulation
state. There is no leaderboard, challenge, server-owned configuration or public
replay admission. Workers limits are documented by
[Cloudflare](https://developers.cloudflare.com/workers/platform/limits/); local
workerd does not prove them.

## Transport and input seam

[`checks/replay.py`](checks/replay.py) converts a `.crd` replay into `.rsi`, the
core's private test transport. It carries no claimed score:

- 256-byte config: 64 little-endian uint32 values, laid out in
  [`host/api.h`](host/api.h).
- Each tick: four float32 axes, uint32 flags, a uint32 command count, then that
  many `(int32 type, int32 argument)` pairs.
- Commands: `1` picks an offered slot, `2` requests the perk menu (argument 0).

The core checks finite input, supported flags, command count, perk entitlement,
choice bounds, dead-player restrictions and terminal states; a rejected tick
leaves the instance unsteppable until it is reinitialized.

The seam is **gameplay ticks plus semantic commands**, not original UI frames.
Commands run in order before a tick; menu requests generate offers and picks
consume entitlement, and a pick can generate dirty offers without a preceding
menu request. Paused menu frames are absent, and the host clears the pending
perk-screen transition. A client must freeze its gameplay clock while showing
that UI and submit commands at this same seam. This is a deliberate modern
rule; native perk-screen timing and RNG equivalence is not claimed.

Aim reaches gameplay as recorded. Mouse aim is a world point used directly:
going through screen space and back lost one F32 ULP against Python, and the
original agreed with each port given its own operands. Pad aim is the stick's
reach, added to the moved position in the native pad block in place of its
stick and cvar read.

## How the build works

[`adapter.py`](adapter.py) applies the modern-compiler changes to generated
copies: C linkage, const references for VC6 temporaries, declaration repairs
and shared math calls. It also keeps selected x87 evaluation boundaries: wide
angle returns, the first player/projectile trig multiply and the quest trig
spills (Sweep Stakes and Deja vu spill cosine to F32 but keep sine wide, which
the original executable established, not the C syntax). Each adaptation is
guarded by an expected match count.

[`data.py`](data.py) recreates the globals from the recovered data manifest.
Adjacent globals stay separate because 64-bit pointers need more storage;
pointer-bearing pools use host `sizeof`, and metadata aliases use the host
stride. Spans the native code reads past their first symbol stay contiguous:
the creature type table runs through `creature_type_count`, which native reads
as the corpse frame of ping-pong-strip creatures (type 7), and the HUD gets a
sentinel slot for a one-past lookup.

[`host/host.cpp`](host/host.cpp) owns the seed, fixed timing, input dispatch,
initialization and output. It keeps the recovered orchestration and the render
functions that clean up corpses and projectiles or consume RNG, and replaces
drawing and device output. Audio is a fixed, successful, silent bootstrap that
keeps the music-selection RNG gate open, as Python assumes; music tracks get
distinct ids in `audio_init_music`'s load order. This is a defined environment,
not a reconstruction of every original startup path.
`CRIMSON_CORE_TRACE_INIT=1` traces native initialization.

[`host/math.zig`](host/math.zig) supplies trig from Zig's bundled math and the
CRT PC24 power model to both targets, so neither depends on the host libc. On
Linux it builds for a baseline CPU with `-fno-builtin`, so the compiler runtime
cannot turn its memory routines into calls to themselves.

Native/WASM agreement establishes modern-build determinism, and one compiled
module removes cross-target layout and compiler variation. Neither makes
undefined C++ behavior safe or establishes original-game correctness; the
original executable is the fidelity oracle.
