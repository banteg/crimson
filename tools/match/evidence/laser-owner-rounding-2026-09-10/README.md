# Native Sharpshooter laser ownership and rounding

Native draws a laser for each living player when **player zero** has
Sharpshooter. The read at `0x422ea8` uses the fixed player-table base plus the
perk-id offset, without the current player's stride. A living second player
therefore receives a laser even if only a dead first player has the perk.
The recovered scratch preserves this behavior. Python uses this owner when
`preserve_bugs` is enabled and retains per-player ownership otherwise.
Ten Python draw-boundary regression cases cover both modes and player deaths;
three failed before the port correction.

The scratch also copies the world-space laser start before adding the camera.
Native stores start Y as float32 at `0x422df1`, reloads it at `0x422e1e`, and
then adds camera Y at `0x422e22`. The preceding compound expression kept that
intermediate extended, changing two Y arguments by one float bit in the first
fixture. With player position `(100, 150)`, heading 0.3, and camera
`(13.125, -21.75)`, the first corner's Y bits are `0x42e22ec0` in native and the
recovered source, versus `0x42e22ec1` in the preceding source. An independent
arithmetic oracle distinguishes these rounding boundaries. This establishes
the required lifetime without uniquely identifying the original C++ spelling.
The Python correction concerns ownership; it does not claim native float-bit
identity for the port's laser geometry.

## Replayable evidence

[`verify.py`](verify.py) compiles the actual source, links COFF relocations,
and runs the native and candidate renderer bodies using the shared
[plasma machine runner](../plasma-head-alpha-2026-09-10/verify.py).
All **438 fixtures** agree on complete ordered caller argument bits and
projectile, player, and creature storage:

- one/two players, all four Sharpshooter ownership combinations;
- three heading pairs and three health pairs, including a dead perk owner;
- transition alpha 0.2/0.7/1.5 and glow disabled/enabled;
- six zero-player controls with populated but out-of-count player records.

An independent count oracle checks the number of laser quads. The verifier
checks the native owner load and float-store sequence directly. Three
separately compiled source controls restore the owner defect, rounding defect,
or both; all **seven negative cases** are rejected. The combined control
recreates the preceding source exactly, SHA-256
`45282781bf6a17603dba64ad58dbfddd925c391bfcc5c694c96bb85450d6472e`.

Grim methods are recording thiscall stubs, texture selection is a recording
no-op, and the perk query returns zero; Sharpshooter counts are read from
actual player memory. Math executes machine x87 and native `crt_ftol` under
control word `0x037f`. Fixtures have no active primary or secondary
projectiles and fixed camera coordinates. Stack balance, callee-saved
registers, allowed instruction addresses, and absence of non-stack writes
are checked. These are caller-behavior fixtures, not full-renderer or pixel
identity. The earlier plasma, beam, and native-search ion-chain packages
are also replayed against this source, covering another **1,064 fixtures**.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/laser-owner-rounding-2026-09-10/verify.py \
  --out /private/tmp/crimson-laser-proof
```

Unicorn requires local JIT permission. [`results.json`](results.json) pins
source, verifier, engine, native image/body, object, relocation, build,
fixture, negative-control, and matching identities.

## Matching progress

Alignment improves from **57.427414% to 59.622514%**, candidate instructions
move from **2903 to 2913** against **3021**, and references improve from
**456/0/11 to 464/0/10**. Both exactness flags remain false; this is partial
recovery and grants no new whole-function match. No matching rule, alias,
or regression exception is changed.
