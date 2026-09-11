# Creature sprite pass order and dimensions

Both ports now finish every shadow of a species before drawing its bodies and
hit flashes. Python also uses the creature's actual size, divided by the atlas
cell width, instead of clamping a hard-coded `size / 64` scale. Zig preserves
native draw submission for fully transparent shadows.

For two zombies followed by one spider, the sprite sequence is now
`zombie shadows → zombie bodies → zombie flashes → spider shadow → spider body
→ spider flash`. Previously each port interleaved a creature's shadow and body.
This matters when a later creature's shadow overlaps an earlier creature's body.
A size-200 creature now has a 200-pixel Python body instead of a 128-pixel body
on a 512-pixel atlas; a size-4 creature retains its 4-pixel body instead of 16.

This changes port rendering, not the C++ reconstruction. `creature_render_type`
remains **79.737705%**, with **760/765 instructions**, references **139/0/5**,
and neither normalized nor encoded exactness. No matched function or byte is
added by this correction.

## Native evidence

[verify.py](verify.py) executes the original `creature_render_type` and the
unchanged compiled C++ object through the existing guarded
[runner](../creature-frame-selection-2026-09-11/runner.py). Complete ordered API
arguments and observed writes agree in **80 comparisons**. The matrix covers
**16 settings combinations** across five species and yields **1,056 sprite
quads**. It varies shadows, Monster Vision, violence-disabled flashes and
Energizer, with sparse active/inactive slots, both animation strips, lifecycle
fading, retirement below -10, sizes from 4 to 200, and the final pool slot.
A trooper is present but excluded from the species sequence.

The observer classifies native batches from the actual source/destination
blend settings. Each draw label is checked against the native quad position;
fixture spacing makes its creature identity unambiguous. Native body/flash
width and height must equal the input size's binary32 words. Every species
finishes its shadow batch before its body and flash batches. The five type
invocations are concatenated in the already recovered `creature_render_all`
order; this verifier does not execute the wrapper or its preceding overlays.

The fixtures use gameplay PC24 (`0x007f`). The parent enforces guarded code
execution, balanced call/return stack, preserved registers and control word,
and allowed writes. Species-table base-frame/mirror initialization and the
compiled field-layout check come from the preceding frame-selection proof.
The fixture executes **720/765 native** and **715/760 candidate** instructions;
it is not an all-input or full-coverage proof. The native image, body, C++
source, parent files, call traces and coverage are identified in
[results.json](results.json).

## Port evidence and regressions

[verify_ports.py](verify_ports.py) checks the shared
[native witnesses](../../../../crimson-zig/src/runtime/testdata/creature-pass-order.json)
against both current ports and immutable baseline
`c8c9cda9922d15a5f95c00ca1247994dd52e51bc`.

Python runs the production world draw function and sprite helper, intercepting
Raylib texture calls. It supplies snapshot/configuration fixtures and replaces
the unrelated overlay pass and perk query. The regression checks exact creature
and pass sequence, atlas frame, and body/flash dimensions. Shadow dimensions
allow a relative tolerance of `1e-6` for the existing backend arithmetic.

The Zig observer compiles **eight current function bodies** extracted from
`window_main.zig`, including the species loops, flash loop, atlas drawing,
conversion helpers (the immutable baseline also extracts its former local
tint helper). It imports the actual atlas, animation, perk and
state modules. [ports.zig](ports.zig) provides only the state envelope,
texture lookup and drawing boundary needed to record those functions. The
renderer reaches the production atlas-rectangle calculation before the draw
observer. This is execution of the extracted production paths, not a second
implementation of their loops. Full native and WebAssembly builds separately
check their integration into the window application.

All **1,056 witnesses** pass at atlas widths **256 and 512** in Python and in
Zig **Debug and ReleaseFast**. Baseline controls fail as expected:

- Both old ports have the wrong ordered sequence in the four combinations
  where shadows are enabled and Monster Vision is absent.
- At atlas width 512, old Python has **240 dimension mismatches** even after
  aligning draws by creature and pass. At width 256 it has **540**; the old
  fixed divisor also ties world size to atlas resolution.
- Old Zig emits **1,052 draws**, dropping four zero-alpha shadows. Its retained
  draws have the correct dimensions within the stated shadow tolerance.

[port-results.json](port-results.json) records source/extraction hashes, compiler
version, observation digests, mismatch counts and representative failures.
The Python native-witness regression runs under the ordinary pytest suite.
The compiled Zig draw observer is reproduced by the evidence command below;
it is additional to the standard Zig suite.

This verifies CPU draw order, selection and dimensions. It does not certify
GPU pixels, exact shadow geometry, tint/alpha arithmetic, rotation conversion,
or lifecycle timing across simulation frames. Native's ZERO/INVSRCALPHA shadow
blend is represented by the ports' existing black-alpha silhouette; alpha-channel
and backend rasterization equivalence are not claimed.

The subsequent [colour audit](../creature-render-colors-2026-09-11/README.md)
checks native float words and packed channels. The port receipts here have
been refreshed after that correction; the native witnesses are unchanged.

## Reproduce

```sh
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/creature-pass-order-2026-09-11/verify.py \
  --out /tmp/crimson-creature-pass-native
cmp /tmp/crimson-creature-pass-native/witnesses.json \
  crimson-zig/src/runtime/testdata/creature-pass-order.json
uv run python tools/match/evidence/creature-pass-order-2026-09-11/verify_ports.py \
  --out /tmp/crimson-creature-pass-ports
uv run pytest --no-cov tests/render/test_creature_pass_order.py \
  tests/render/test_world_draw_order.py
```

Run `zig build test --summary all`,
`zig build test -Doptimize=ReleaseFast --summary all`,
`zig build -Doptimize=ReleaseFast` and `zig build wasm` from `crimson-zig`.
The native verifier requires Unicorn JIT permission on macOS; compiler-backed
checks require access to their normal caches.

Final validation passed **3,746 Python tests** (10 skipped) and **135 snapshots**,
**753 Zig tests** in each build mode, and both native/WebAssembly builds. Ruff,
types, import contracts, documentation checks and ast-grep checks passed.
Native game-owned closure remains current for both images; the matching
regression check reports zero changed functions and zero regressions, and the
strict experiment ledger has zero errors.
