# Creature body and shadow colours

The Python and Zig sprite renderers now preserve the native colour arithmetic:
Energizer uses `(1 - t) * base + t * target`, corpse fading follows that blend,
and transition alpha is applied last. Each operation rounds at gameplay PC24.
Grim2D truncates each scaled channel and keeps its low byte; the ports previously
rounded and clamped their body colours.

For an alive weak creature with tint `(0.8, 0.7, 0.6, 0.9)`, no Energizer, and
transition `0.8`, native submits RGBA **(204, 178, 153, 183)**. Both previous
ports submit **(204, 179, 153, 184)**. Their shadow arithmetic also differs on
some fade and byte boundaries. The common flash byte converter now uses the
same helper and retains its previously verified output.

This corrects port rendering. The C++ reconstruction is unchanged at
**79.737705%**, **760/765 instructions**, references **139/0/5**, with neither
normalized nor encoded exactness. This adds no matched function or byte.

## Native evidence

[verify.py](verify.py) executes the original `creature_render_type` and compiled
C++ through the existing guarded [runner](../creature-frame-selection-2026-09-11/runner.py).
Complete ordered API arguments and observed writes agree in **40 comparisons**.
The matrix contains **27 creatures**, **eight Energizer values** and **five
transition values**, producing **4,320 quads**: 1,080 shadows, 1,080 bodies and
2,160 additive flashes. It includes both animation strips, lifecycle values
-2, -0.125, 0 and 16, health below/at/above 500, black/white/intermediate tints,
zero alpha, and two bounded negative/overbright diagnostic tints.

The observer classifies batches using native blend settings and checks each
creature label against its actual quad position. It records the four native
float words passed to `grim_set_color_ptr`, then executes that original Grim2D
function for each of **375 distinct inputs**. Its imported `_ftol` is bound to
the game's original CRT converter, an explicit model of that import. The
[existing colour runner](../creature-hit-flash-2026-09-11/verify.py) checks
permitted instruction addresses and writes, stack/register/control-word
preservation, FPU stack balance, copied float words and packed output.

The gameplay control word is `0x007f`. This matrix executes **677/765 native**
and **672/760 candidate** creature-renderer instructions. The colour runner
covers 42 instructions across Grim2D and the bound CRT converter. This is a
bounded arithmetic proof, with finite inputs whose scaled channels fit signed
32-bit conversion. It does not cover NaNs, infinities, conversion overflow or
x87 extended-exponent extremes. [results.json](results.json) identifies the
images, source, body, parent script, layout, traces, coverage and witnesses.

## Port execution and regressions

The shared [native records](../../../../crimson-zig/src/runtime/testdata/creature-render-colors.json)
feed both ordinary test suites. Python and Zig each check **2,160 body/shadow
records**, including exact pre-packing binary32 words. Checking float words
prevents byte quantization from hiding incorrect blend order. Native shadow
RGB is ignored by its ZERO/INVSRCALPHA blend; the ports retain their black
silhouette adapter and compare the exact native alpha.

[verify_ports.py](verify_ports.py) additionally executes the actual Python draw
caller and sprite helper, and compiles unchanged rendering functions extracted
from Zig's `window_main.zig`. [ports.zig](ports.zig) binds their required state,
texture lookup and draw boundary; atlas, animation, perk and colour helpers
come from production modules. Eight current function bodies are extracted;
the immutable baseline also includes its former local tint helper. This
checks production rendering paths through the texture-call boundary without
requiring a graphical window. Native and WebAssembly builds check integration.

Python's observer identifies shadows from the sprite call's shadow argument,
so a black body remains a body. The Zig observer identifies the pass from
quad dimensions and additive state, with independent position/size assertions.
Both record the submitted RGBA bytes, creature index, pass and atlas frame.

All **4,320 draws** match in Python at atlas widths **256 and 512**, and in Zig
**Debug and ReleaseFast** at both widths. Immutable baseline
`4e9ef68d2464228c4b67fd4db87bf0972f032a47` differs in every matrix case:

| Baseline | Body mismatches | Shadow mismatches | Flash mismatches |
| --- | ---: | ---: | ---: |
| Python | 790 | 256 | 0 |
| Zig, either mode | 808 | 24 | 0 |

Counts are per atlas width. [port-results.json](port-results.json) stores
source/extraction hashes, compiler version, output digests and representative
failures. The earlier pass-order/dimension observer also still passes all
1,056 records with the updated helpers.

The proof concerns CPU arguments inside species rendering, not GPU pixels,
framebuffer alpha equivalence, surrounding world-render gates, or exact
rotation/geometry arithmetic. It does not execute `creature_render_all` or
its aura overlays. Existing missing-texture fallbacks are outside the matrix.

## Reproduce

```sh
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/creature-render-colors-2026-09-11/verify.py \
  --out /tmp/crimson-creature-colors-native
cmp /tmp/crimson-creature-colors-native/witnesses.json \
  crimson-zig/src/runtime/testdata/creature-render-colors.json
uv run python tools/match/evidence/creature-render-colors-2026-09-11/verify_ports.py \
  --out /tmp/crimson-creature-colors-ports
uv run pytest --no-cov tests/render/test_creature_render_colors.py \
  tests/render/test_creature_pass_order.py tests/render/test_world_draw_order.py
```

From `crimson-zig`, run `zig build test --summary all`,
`zig build test -Doptimize=ReleaseFast --summary all`,
`zig build -Doptimize=ReleaseFast` and `zig build wasm`.
The native verifier needs Unicorn JIT permission on macOS. Compiler-backed
checks require access to their normal caches. The compiled draw observer is
additional to the ordinary Zig suite's exact colour-word regressions.

Final validation passed **3,866 Python tests** (10 skipped) and **135 snapshots**,
**753 Zig tests** in each mode, and both native/WebAssembly builds. Ruff,
types, import contracts, documentation and ast-grep checks passed. Native
function/game-owned closure is current for both images; the matching
regression check reports zero changed functions and zero regressions, and
the strict experiment ledger has zero errors.
