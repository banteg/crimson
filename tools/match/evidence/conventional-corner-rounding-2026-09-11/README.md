# Conventional projectile corner rounding

The reconstructed `projectile_render` shared scaled width and screen-position
temporaries across its four conventional trail corners. VC6 kept or spilled
different X values from native. Complete vector expressions at the individual
corners recover the native store boundaries without volatile variables, assembly,
padding, compiler overrides, or reference aliases.

The native argument oracle and retained C++ agree on **4,118 complete caller
fixtures**. The previous source fails **61 of the 1,280 discovery fixtures**:
21 Pistol, 23 Gauss, and 17 catch-all cases. These differences occur under the
diagnostic 64-bit-significand x87 control word `0x037f`. Both sources agree in
the discovery matrix under the game's 24-bit-significand mode, `0x007f`; this
does not establish a visible gameplay regression in the previous source.

All **2,696 earlier plasma, beam, ion-chain, Sharpshooter, and secondary-rocket
fixtures** retain their complete native trace hashes. The Python and Zig ports
are unchanged by this C++ source-recovery step.

## Native arithmetic

The four branch windows are `0x4230e5..0x4231ea` (Assault),
`0x4231f3..0x423345` (Pistol), `0x423395..0x4234e7` (Gauss), and
`0x4234e7..0x42363a` (catch-all). They feed `grim_draw_quad_points` at
`0x42365d`.

- Width factors are float32 `1.0`, `1.2`, `1.1`, and `0.7`, respectively.
- The scaled X product is stored without being popped. Origin corners use
  the stored float32 width; head corners retain the wider product.
- Origin X retains its camera sum through subtraction/addition. Origin Y
  uses a stored float32 camera sum.
- Scaled head X is stored while its wider camera sum remains live for the
  plus corner. The minus corner reloads the stored sum. Assault instead
  duplicates the wider head sum for both corners.
- Head Y and Y width use their float32 stores in both head corners.

`fixtures.py` evaluates these operations with exact rational arithmetic,
rounding each arithmetic result to the selected 24- or 64-bit significand and
each native store to binary32, nearest with ties to even. Conversion to a
Python float occurs only after the result is binary32-representable. The
oracle is bounded to the finite, normal-range fixtures; it does not model
exceptions, subnormals, NaNs, or alternative rounding modes.

The previous-source oracle independently reproduces all 1,280 compiled old
corner records: it retains the wide origin width, stores Pistol/Gauss head X
too early for the plus corner, and retains catch-all head X too long for the
minus corner. Each rejected case differs at exactly one draw call, with
unchanged pool state.

## Proof and reproduction

Run from the repository root with the optional pinned Unicorn dependency and
local JIT permission:

```sh
uv run --with unicorn==2.1.4 python tools/match/evidence/conventional-corner-rounding-2026-09-11/verify.py --out /tmp/conventional-corners
uv run --with unicorn==2.1.4 python tools/match/evidence/conventional-corner-rounding-2026-09-11/replay_regressions.py --out /tmp/conventional-regressions
```

`before.cpp` is the immutable preceding source. `execute.py` reuses the
COFF-relocating program loader from the plasma evidence package, with a
dedicated conventional-projectile executor. A VC6 compile checks the record
size, field offsets, pool extent, and type IDs. The proof checks native
instructions and constant bytes at the relevant store boundaries.

| Fixture group | Cases |
| --- | ---: |
| Seeded discovery geometry, four branch families, both precision modes | 1,280 |
| Slots 0/1/47/95, all nine conventional IDs, lifetime/alpha/glow gates | 1,728 |
| Inactive and noncanonical nonzero active bytes | 36 |
| Empty pool | 8 |
| Mixed types and sparse/dense pool layouts | 36 |
| Changing camera, origin, head, and velocity | 1,024 |
| Coincident endpoints and zero/axis widths | 6 |

`fixtures.jsonl` stores every input, native corner words, complete call-trace
hash, pool hashes, writes, and exercised-instruction counts. `results.json`
binds that file to the sources, compiler build key, candidate object/body,
native image/body, relocation map, instruction windows, and rejected cases.
`regressions.json` binds the five earlier immutable receipts to the current
candidate.

The executor verifies the return address and caller stack guard, callee-saved
registers, balanced x87 tags, and unchanged control word. Recording Grim and
effect/perk stubs clobber volatile registers. Type zero may clear only its
own active byte; all other primary fields and the complete secondary,
player, and creature pools remain unchanged. No unmodeled execution or
non-stack write is accepted.

## Matching tradeoff

| Metric | Previous | Retained | Native |
| --- | ---: | ---: | ---: |
| Match ratio | 60.323887% | 59.946417% | 100% |
| Instructions | 2,907 | 2,951 | 3,021 |
| Stack frame | `0x144` | `0x184` | `0x19c` |
| References: good / unresolved / mismatched | 466 / 0 / 10 | 470 / 0 / 12 | — |

The lower score is retained for the directly verified arithmetic correction.
Both exactness flags remain false and the exact prefix remains zero. Native's
remaining frame difference is not evidence for adding unused locals.

The positional reference audit changes two ion-fading pairings into four;
the other eight mismatch addresses persist. A regression waiver names the
exact preceding commit and this proof. All twelve mismatches remain reported;
neither the matcher nor any reference alias is changed. This evidence proves
the listed caller traces, not GPU output, all-input equivalence, original
source identity, or a whole-function match.

## Python PC=24 follow-up

The Python renderer had a separate discrepancy in the game's normal precision
mode: it carried camera sums, width products, and corner additions in Python
binary64 until submitting the final vertex. Capturing the actual registry
dispatch and `rl_vertex2f` arguments found **292 differing records out of the
640 PC=24 discovery cases**.

`bullet_trail_corners` now narrows input fields and width constants, rounds the
camera sums and scaled velocity, then rounds each corner addition/subtraction.
The draw helper accepts world positions and applies the viewport transform to
the completed native corners. Unequal viewport scales therefore apply to each
coordinate independently, instead of averaging the axes for width alone.

`verify_ports.py` checks **1,161 recorded native fixtures at three viewport
scales**: `(1, 1)`, `(2, 2)`, and `(1.5, 0.75)`. All 3,483 current cases pass.
The exact preceding Python modules from commit `544af3e05` fail 726 cases at
unit scale, 726 at doubled scale, and 1,160 at unequal scales. All recorded
non-vertex GL calls remain identical between the two renderers, including
colors, UVs, texture selection, and blend/batch calls. The regular renderer
tests cover 64 native records at each scale, adding 192 exact argument checks.

```sh
uv run --no-sync python tools/match/evidence/conventional-corner-rounding-2026-09-11/verify_ports.py --out /tmp/conventional-python
```

This command consumes the already verified native fixture file; it does not
require Unicorn or execute the original binary again. `port-results.json`
records the native receipt and fixture hashes, current and historical Python
source hashes, submitted-vertex/trace hashes, and old-renderer differences.
It covers positive-alpha trails for the six represented Python types
`1/2/3/5/6/29`. Native-only IDs `0/4/7` are excluded. The fixture exposes only
the trail texture, so this proof does not cover sprite heads, world-level
visibility gates, simulation mutations, or GPU pixels. Zig remains unchanged.
