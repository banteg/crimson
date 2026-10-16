# Crimson core

The recovered C/C++ gameplay from [`decomp/`](../decomp) built into one
deterministic simulation, as a native executable and an import-free WASM
module: the replay verifier, which the leaderboard runs on every upload
([`service/src/verify.ts`](../service/src/verify.ts)). The native and web clients run the whole recovered
game around the same gameplay sources and are held to this verifier on every
gate stream ([PORT.md](PORT.md)). Python stays the reference port for fast
iteration.

`decomp/` stays the matching source of truth. The core compiles generated
copies of the recovered translation units in [`sources.json`](sources.json);
everything it adds lives here.

## Status

- Whole runs agree with Python under both bug policies: the **original rules**
  (`preserve_bugs=True`) and the **ranked rules** (`preserve_bugs=False`, the
  documented fixes). The [gate](#whole-run-gate) checks every bot stream and
  supported recording in CI, and the core reproduces the recordings' claimed
  results.
- Native and WASM snapshots are bit-exact on every bot run, including resets
  ([matrix](#nativewasm-matrix)). Quest builders and gameplay math match the
  original executable.

## Scope

- One or two players at a fixed 60 Hz in Rush, Survival, all 50 Quests and
  custom quests ([`CustomQuest`](../src/crimson/quests/custom.py)); two
  players are the groundwork for [network co-op](../docs/rewrite/network-coop.md).
  The game module's live play, replays and the service stay one-player.
- Every movement scheme (relative, static, dual action pad, point-click and
  computer) and aim scheme (mouse, keyboard, joystick, mouse-relative, pad and
  computer), read from each tick's flags as Python does; see
  [the input seam](#transport-and-input-seam), each player's from their own
  input. Typ-o, the tutorial and more players fail explicitly.
- The run's bug policy comes with its configuration; see [Rules](#rules).

## Low-level bot API

The verifier's initialization and stepping exports are a supported low-level API
for bot harnesses: `portable_config`, `portable_init`, `portable_input`,
`portable_commands`, `portable_step_many` and the single-command wrapper
`portable_step`. Their buffer layouts are declared in [`host/api.h`](host/api.h);
the [input seam](#transport-and-input-seam) defines command timing. An instance
holds one run, so concurrent simulations require separate module instances.
Breaking API or layout changes must include migration notes for callers.

Migration: `PortableConfig` has a 13th setting, `players`, after `preserve_bugs`
(264 bytes; write 1 for a one-player run, which a zero refuses), and
`portable_input` points at one `PortableInput` per player, player one first.

Write the configuration before initializing, then write the input and up to 16
commands before each step. To play a custom quest, also write its table at
`portable_quest` (`PortableQuest`) and initialize a quest at stage 0.0 (major and
minor 0); initialization refuses a table the Python definition would reject. Initialization and stepping return 1 on success and
0 on refusal. After a refused step, reinitialize before continuing: earlier
commands may already have changed the state, so retrying is not transactional.
`portable_refusal` returns a NUL-terminated human-readable reason for the last
step, empty after a successful step. Copy it before stepping again. It does not
diagnose initialization failures, and its wording can change; do not parse it
as a machine-readable error code.

Internal parity snapshots (`portable_snapshot`, `portable_output` and
`schema.json`) and diagnostic probes can change with the implementation. A bot
using them must pin its core build and schema together. This API does not define
a stable bot observation format or a language-specific SDK.

## Layout

| Path | Contents |
| --- | --- |
| [`build.py`](build.py), [`adapter.py`](adapter.py), [`data.py`](data.py) | Generate, adapt and compile the recovered sources; recreate the globals. |
| [`sources.json`](sources.json), [`schema.json`](schema.json) | Selected bodies, snapshot fields. |
| [`host/`](host) | The host the recovered code runs in: API, input, timing, stubs, portable math. |
| [`abi/`](abi), [`seams/`](seams), [`optimizations/`](optimizations), [`patches/`](patches) | Diffs against `decomp/`: compiler repairs, the recording in place of live reads, behavior-preserving optimizations, and the ranked rules, one patch per fixed original bug. |
| [`checks/`](checks) | Native/WASM matrix, Python whole-run gate, original-executable oracles, Wasmtime probe. |
| [`results/`](results) | Checked-in results of those checks. |
| [`game.py`](game.py), [`game/`](game), [`client/`](client) | The game module (the whole recovered game over a platform layer) and its native and web clients; see [PORT.md](PORT.md). |

## Build

Run from the repository root. Requires clang++, wasi-sdk **34.0** (at
`WASI_SDK_PATH`, else the main checkout's `artifacts/wasi-sdk` or `/opt/wasi-sdk`; WASM
targets only), Node.js and the
project's Python environment. Tested on macOS ARM64; CI runs Linux x86-64.
The transport assumes little-endian hosts.

```sh
uv run python crimson-core/build.py
uv run python crimson-core/build.py --target wasm
```

Outputs land in `crimson-core/build/{native,wasm}`. Recovered sources are read
as they are and changed in generated copies ([How the build
works](#how-the-build-works)): every diff hunk must match its exact text once
and every pass its expected number of sites, so a decomp edit that moves one
stops the build there. `--prepare` writes the adapted sources and
`adapted.diff`, everything the target changes from `decomp/`, without
compiling.

## Checks

### Native/WASM matrix

```sh
node crimson-core/checks/matrix.mjs
```

An ordinary bot reads state, chooses inputs and perks, and never edits
simulation state. Each of its scenarios runs under the original rules,
alternating mouse and pad aim, with one scenario per other movement and aim
scheme, and continuing through the run-down after the end. The matrix then
replays that input under the ranked rules: where every tick reaches the same
state (apart from the Shock Chain slot the host sets per policy), the ranked
run would be the same run and is not kept; elsewhere the bot plays it again as
a `-ranked` stream. The input-only `.rsi` streams land in `build/fixtures`.
Two hunter scenarios prefer the perks ranked fixes
touch (Jinxed, Pyrokinetic, Highlander, Death Clock, Bandage, the
Regenerations) and hold G at times; the Highlander hunter's run reaches no
fix, so it runs once. Two Survival scenarios carry quest difficulty: with the Hardcore box ticked
the milestone waves play hardcore under the original rules, and with a quest
retry count they play eased; under the ranked rules each is the plain run,
state for state. The matrix compares every named field of
[`schema.json`](schema.json) at initialization and **every tick** between native and WASM, then checks A/B/A
reuse in both. It also probes rejection of bad input, commands, entitlement and
picks and menu requests the perk rules do not allow, each for the reason both
builds give (`portable_refusal`), and that a large movement vector does not
move faster than a unit one.

The [results](results/matrix.json) list each stream with its ticks, coverage
and hashes. All 50 quests run to an outcome; the bot completes 1.1, 1.3 and 1.5. Custom quests built from
recipes run too (two examples, the stock 1.1 recipe, which the bot completes, and a hardcore one), after a
probe that neither build starts a malformed one. Coverage includes game over in
every mode, quest completion and failure, spawn stalls, reloads, perk menus, a
pick followed by reopening the menu, several weapons, freeze, Reflex Boost and
weapon power-ups, and a settings case varying hardcore, retry scaling, detail,
violence, friendly fire and weapon-usage history. The snapshot is a diagnostic schema: pointers
become pool indices, and padding, static addresses, draw vertices and
presentation-only HUD slots are left out. It is not a save-state format.

A single stream can be replayed with
`node crimson-core/checks/compare.mjs <stream.rsi> <native core> <core.wasm>`.

### Whole-run gate

```sh
uv run python crimson-core/checks/gate.py --out crimson-core/results/gate.json
```

The gate feeds each bot stream and each supported recorded fixture to Python
and the native core, both under the bug policy the stream's configuration
carries; recorded fixtures replay under the rules they were recorded with. Per tick it compares the RNG state, kills, shots, pending
perks, bonus timers and each player's position, health, death timer, headings,
experience, level, ammo and weapon, floats as F32 bits, keeping the first
divergence. It compares the terminal tick and outcome, and the complete
`RunResult` after the last tick both stepped. Both sides simulate the run-down
after the end, at most 500 ms of frames, as live play and verification do; a
core rejection counts only where Python's run-down ends, and the gate refuses
to run on a partial bot corpus or unknown `--only` names.

Python steps each stream through its verification `PlaybackDriver`, so a
recorded fixture is also checked against its claimed result and every `.chk`
checkpoint in the same pass. The [baseline](results/gate.json) records each
stream's agreement, including the supported recorded fixtures (quests, Survival
and Rush, with pad, keyboard-and-mouse and tank controls, one of them a
Survival run whose dead player gets back up from a MediKit), and lists the
unsupported Typ-o fixture. CI fails on any disagreement. A new divergence is reduced to its first differing state and
decided against the original through Unicorn or its disassembly.

### Original executable

The oracles call the original code through Unicorn, using the ignored game
binary; CI downloads it and runs both oracles and the [Wasmtime
probe](#same-wasm-from-python). Unicorn's JIT must run outside the command
sandbox, as documented in `tests/native_oracle/conftest.py`.

```sh
uv run python crimson-core/checks/builder_oracle.py \
  --exe game_bins/crimsonland/1.9.93-gog/crimsonland.exe \
  --out crimson-core/build/oracle.json
uv run python crimson-core/checks/math_oracle.py \
  --exe game_bins/crimsonland/1.9.93-gog/crimsonland.exe \
  --out crimson-core/build/math-oracle.json
```

- [Quest builders](results/builder-oracle.json): all spawn-table fields, entry
  counts and final RNG states for every builder over fixed seeds (`SEEDS` in
  [`builder_oracle.py`](checks/builder_oracle.py)), normal and hardcore, agree,
  native and WASM alike. Later quest-start difficulty adjustments are not
  covered.
- [Gameplay math](results/math-oracle.json): cases checked against original x87
  instructions, covering Normalize (near-unit, `FLT_MIN` and every finite F32
  exponent range, separate and in-place destinations), CRT power and level
  thresholds, and movement trig products. The core has no mismatches. Python's
  few extreme vector discrepancies (`python_original_mismatches`) come from
  rounding a subnormal result straight to F32 instead of to PC24 first.
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
the [service](../service/src/verify.ts) in
[wasmtime-py](https://bytecodealliance.github.io/wasmtime-py/), compares the hash of every snapshot of a smoke set (one run per mode, bug
policy and control family) and checks A/B/A resets in one instance, without
adding a project dependency; the matrix already compares every run between
native and Node. The results record the module's hash and its linear memory.

## Rules

The run configuration's `preserve_bugs` sets `portable_preserve_bugs`
([`host/rules.h`](host/rules.h)). Each documented Python fix the core's scope
reaches is a patch in [`patches/`](patches), named after its entry in
[`docs/rewrite/original-bugs.md`](../docs/rewrite/original-bugs.md). The fix
sits at the native site behind the flag, `if (portable_preserve_bugs) {native}
else {fix}`, so the RNG call order matches Python under both policies, and
`decomp/` stays untouched. The patches are diffs against `decomp/`, which the
build applies by exact text, ignoring line numbers; a hunk that no longer
matches exactly once stops the build. Bug 32 (the Shock Chain slot's starting
value) is set by the host at run start, and bug 15 (player 2's joystick hat) is
the input seam: each player's turn flags arrive with their own input.

| Patch | Fix |
| --- | --- |
| 01 | Weapon drops are suppressed only for a weapon a player carries, not any matching amount |
| 02 | Greater Regeneration doubles the Regeneration heal |
| 03 | Bandage adds its roll to living players instead of multiplying |
| 05 | The reload preload looks ahead by the Stationary Reloader step |
| 06 | A Weapon drop turns into Points near any player |
| 07 | Regeneration heals each living player once |
| 09 | A hit's was-alive guard reads the hit player's health |
| 10 | Jinxed can pick the last creature slot |
| 11 | Doctor, Pyrokinetic and Evil Eyes work from each living player's aim |
| 12 | The Jinxed accident hurts a random living player |
| 13 | Fire Bullets converts only its shooter's shots |
| 14 | Pyromaniac is offered while any living player holds the Flamethrower |
| 16 | The Pistol fallback drop roll checks every player's weapon |
| 17 | Mini-Rocket Swarmers spread evenly over 120 degrees around the aim |
| 18 | Exactly 0 health is lethal |
| 19 | Co-op auto-targets compare distances from the targeted player; a dead partner's reevaluation is defined under both policies |
| 20 | A nearest-creature search that finds nothing returns -1 |
| 23 | Plaguebearer infects by touch from every player |
| 24 | Holding G grants no Fire Bullets |
| 27 | Enemy projectiles do not hurt through Death Clock |
| 33 | A bonus carrier drops its bonus once |
| 38 | The saved Hardcore box and the failed-quest retry easing apply to quests only, not to Survival's milestone waves or the Tutorial |
| 40 | The reload key reloads in co-op |

Fixes that only change what is drawn are patches in
[`game/patches/`](game/patches), which only the game module applies, so the
verifier stays byte-identical:

| Patch | Fix |
| --- | --- |
| 08 | Player 2's heart pulses by their own health |
| 25 | A re-picked bonus's HUD indicator slides straight back in |
| 28 | Bullets and pellets show their heads |
| 34 | Each Fire Bullets shot glows, and nothing else does |
| 35 | Rocket detonation flashes draw the soft glow cell |
| 36 | Ion chain arcs close in round end caps |

The client's live input ([`host/session.inc`](host/session.inc)) keeps a resting
pad aim stick on its last direction (31). The other entries are out of the
core's scope (co-op, Typ-o, menus) or are documentation only.

## Transport and input seam

[`checks/replay.py`](checks/replay.py) converts a `.crd` replay into `.rsi`, the
core's input stream as a test file; the service builds the same stream in
memory ([`service/src/transport.ts`](../service/src/transport.ts)). It carries
no claimed score:

- 264-byte config: 66 little-endian uint32 values (13 settings ending with
  `preserve_bugs` and the player count, 1 or 2, then 53 weapon usage counts),
  laid out in [`host/api.h`](host/api.h).
- A quest at stage 0.0 plays a custom quest, whose 6,164-byte `PortableQuest`
  follows the config: its starting weapon, three terrain slots and entry count,
  then 256 entries of three float32 (position, heading) and three int32
  (template, trigger time, count). It is the one-player table for the run's
  hardcore setting with base counts; the start applies the hardcore rule.
- Each tick: each player's four float32 axes and uint32 flags, player one
  first, a uint32 command count, then that many `(int32 type, int32 argument)`
  pairs. Perk commands are the team's: the replay's `player_index` does not
  reach the simulation.
- Commands: `1` picks an offered slot, `2` requests the perk menu (argument 0).

The core checks finite input, supported flags, command count, perk entitlement,
choice bounds, dead-player restrictions and terminal states; a rejected tick
leaves the instance unsteppable until it is reinitialized.

The seam is **gameplay ticks plus semantic commands**, not original UI frames.
Commands run in order before a tick. A menu request opens the menu during that
tick; the following tick may pick once, consuming entitlement, and a tick
without a pick cancels the menu. A pick may request another menu in the same
tick if it leaves a pending perk and a living player. Paused menu frames are
absent, and the host clears the pending
perk-screen transition. A client must freeze its gameplay clock while showing
that UI and submit commands at this same seam. This is a deliberate modern
rule; native perk-screen timing and RNG equivalence is not claimed.

Aim reaches gameplay as recorded. Mouse aim is a world point used directly:
going through screen space and back lost one F32 ULP against Python, and the
original agreed with each port given its own operands. Pad aim is the stick's
reach, added to the moved position in the native pad block in place of its
stick and cvar read. Mouse-relative aim is the cursor's screen position, and
point-click movement takes the recorded move target in the move axes (x = -1
for none) in place of the reload key and cursor. Held movement keys and the
aim turn keys arrive as flag bits through `grim_is_key_active`, each player's
under their own codes (player two's fire key, move axes and keys are 200, 2-3
and 0x110-0x115), and the shared reload and G keys read the updating player's
input. Each player's mouse-relative cursor is their own, where the original's
players share one mouse; the joystick
scheme's POV hat reads the same turn bits.

## How the build works

Every source is read as `decomp/` has it and changed in two steps
([`adapter.py`](adapter.py)). Diffs make the edits that belong to one place:
[`abi/`](abi) repairs what a modern compiler rejects (a `LARGE_INTEGER` view,
calls and definitions that disagree on arguments, `size_t` spelled as a 32-bit
int), [`seams/`](seams) puts the recording where the original reads live input,
behind `PORTABLE_RECORDED`, which the verifier fixes at 1 and the game module
sets inside a tick, and a custom quest where it reads the quest table, [`optimizations/`](optimizations) changes performance while
preserving both bug policies, and [`patches/`](patches) holds the ranked rules;
the game module adds [`game/changes/`](game/changes) and [`game/patches/`](game/patches).
A diff names its files by their paths from the repository root and reads
against them as `decomp/` has them; a hunk matches by its exact old text, which
must occur once. Passes then make the edits a rule decides, each expecting its
number of sites, and the code a diff adds takes them too: the x87 boundaries
below, C linkage, const references for VC6 temporaries, the signatures the
recovered files disagree on (`PROTOTYPES`: every declaration takes its
definition's) and shared math calls. Every recovered source sees
[`host/hooks.h`](host/hooks.h), which declares what the edits call.

The x87 passes keep the evaluation boundaries the original executable shows,
which the C syntax alone does not: wide angle returns
(the creature target heading, the Shock Chain link angles), the first trig
multiply of player, projectile, seeker and creature motion and of the player's
aim point, the shot spread and
a projectile's hit jitter and particle velocities (creature movement multiplies
from the cosine left to right), and the quest trig spills (Sweep Stakes and Deja
vu spill cosine to F32 but keep sine wide). In `projectile_update` a cast trig
result multiplied directly stays wide, while a stored one is spilled. Player
XP is an int the original loads exactly (`fild`) into its first PC24 operation
(kill rewards, Radioactive, Energizer, Jinxed, Regression Bullets, Grim Deal and
the Survival spawn health), where a cast to `float` would round it again past
2^24. Each pass names its expected sites; the quest spills apply wherever a
builder uses them, and [`checks/builder_oracle.py`](checks/builder_oracle.py)
runs every builder against the original executable.

[`data.py`](data.py) recreates the globals from the recovered data manifest.
Adjacent globals stay separate because 64-bit pointers need more storage;
pointer-bearing pools use host `sizeof`, and metadata aliases use the host
stride. Spans the native code reads past their first symbol stay contiguous:
the creature type table runs through `creature_type_count`, which native reads
as the corpse frame of ping-pong-strip creatures (type 7), and the HUD gets a
sentinel slot for a one-past lookup. Each span is 16-aligned and keeps native
offsets, so many names sit below the 16 bytes the x86-64 ABI promises a large
array (`weapon_usage_time` at 4); the build gives every `extern` declaration of
such a name its real alignment, or clang vectorizes copies into `movaps`.

[`host/host.cpp`](host/host.cpp) owns the seed, fixed timing, input dispatch,
initialization and output. Its frame step is `game_frame_update`'s: Reflex
Boosted slows the frame by 0.9 while the world renders, and after a run ends
the core keeps simulating until the 500 ms UI timeline runs out, then refuses
input. Globals the original never resets between runs get a fresh game's
values at the start of each run. It keeps the recovered orchestration and the render
functions that clean up corpses and projectiles or consume RNG, and replaces
drawing and device output. Audio is a fixed, successful, silent bootstrap that
keeps the music-selection RNG gate open, as Python assumes; music tracks get
distinct ids in `audio_init_music`'s load order. This is a defined environment,
not a reconstruction of every original startup path.
`CRIMSON_CORE_TRACE_INIT=1` traces native initialization.

[`host/math.c`](host/math.c) builds musl 1.2.5's `sin`, `cos`, `atan2`, `pow`
and `log2` ([`host/musl`](host/musl), verbatim) and the CRT PC24 power model
into every target, so no result depends on the host libm or on fused
multiply-add.

Native/WASM agreement establishes modern-build determinism, and one compiled
module removes cross-target layout and compiler variation. Neither makes
undefined C++ behavior safe or establishes original-game correctness; the
original executable is the fidelity oracle.
