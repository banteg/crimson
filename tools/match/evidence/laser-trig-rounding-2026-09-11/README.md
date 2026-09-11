# Sharpshooter laser trig-store recovery

The Sharpshooter prefix of `projectile_render` (`0x00422c70`) scales its
near-end cosine and both width components while the x87 trig results are
still wide. Constructing the direction vector before multiplying introduced
two premature float32 stores in the previous reconstruction: near-end cosine
and width sine. These stores change submitted corner words under both the
game's PC24 setting and diagnostic PC64.

The corrected source constructs the vector from the scaled components and
adds the near offset to a copy of the player's position. The far-end sine
keeps its distinct, native float32 store before scaling by 512. No compiler,
matcher, alias, Python, or Zig change is part of this correction.

## Evidence

[`verify.py`](verify.py) compiles the current source and the immutable
[`before.cpp`](before.cpp), then executes each beside the original image.
[`execute.py`](execute.py) relocates the object using the existing renderer
loader and records all Grim, effect, and perk arguments. It checks caller
stack guards, callee-saved registers, balanced x87 state, unchanged control
words, and all four pool hashes. The laser fixtures permit no non-stack
writes. External recording stubs clobber volatile registers; unexpected
instruction execution fails the run.

The [receipt](results.json) covers **5,040 native/candidate cases**:

| Group | Cases | Scope |
| --- | ---: | --- |
| Discovery | 1,024 | 512 seeded positions/headings/cameras, each at PC24 and PC64 |
| Extension | 3,072 | 1,536 additional geometries from the same deterministic stream |
| Gates and alpha | 864 | Zero to two players, ownership combinations, health gates, six alpha values, glow on/off |
| Axes and cancellation | 80 | Signed zero and axial headings, camera cancellation, both control words |

All **2,520 PC24 cases** also agree with an independent arithmetic oracle
using wide trig results and explicit native float stores. The original
executable supplies the expected values; the oracle does not derive them
from the candidate source. Ordinary finite inputs and headings in `[-10, 10]`
are covered. This does not establish all-input trig equivalence or GPU pixels.

The rejected source fails **19 cases: 9 at PC24 and 10 at PC64**. Every
difference is confined to the submitted laser corner arguments; ordered
non-geometry calls and pool states agree. Complete inputs, native corner
words, initial color arguments, trace hashes, and pool hashes are stored in
[`fixtures.jsonl`](fixtures.jsonl). The receipt includes each rejected case's
differing call arguments and typed native instruction assertions.

[`probe_controls.py`](probe_controls.py) records seven local expression
controls against 70 discovery witnesses. Fixing only the width leaves four
failures; fixing only the near-end expression leaves two. The selected
component-scaled, compound-add form fixes both. A direct coordinate sum
still fails one PC64 witness despite retaining only twelve positional
reference mismatches. These are bounded controls, not a source-shape ceiling.
See [`source-controls.json`](source-controls.json).

## Regression coverage

- [`conventional-regression.json`](conventional-regression.json): all **4,118**
  recorded conventional trail cases preserve native corner words, full call
  hashes, pool hashes, and writes, replayed by
  [`replay_conventional.py`](replay_conventional.py).
- [`regressions.json`](regressions.json): all **2,696** earlier plasma, beam,
  ion-chain, laser-owner, and secondary-projectile cases preserve their
  original native trace hashes through the preceding package's
  [`replay_regressions.py`](../conventional-corner-rounding-2026-09-11/replay_regressions.py).

The receipts bind the same canonical source and compiled function-body hash.
Raw COFF hashes can differ between forced compilations due to object metadata.
Historical proof packages remain immutable.

## Matching impact

| Metric | Before | Current |
| --- | ---: | ---: |
| Instruction similarity | 59.946417% | 60.268007% |
| Candidate instructions, native 3021 | 2951 | 2949 |
| Frame allocation, native `0x19c` | `0x184` | `0x184` |
| References: OK / unresolved / mismatched | 470 / 0 / 12 | 471 / 0 / 13 |
| Prefix instructions | 0 | 0 |
| Exact / body-byte-exact | false / false | false / false |

[`reference-audit.json`](reference-audit.json) retains all previous twelve
mismatch addresses and adds one positional pairing at native `0x00422e22`:
native camera Y is aligned with candidate camera X. Native execution over
the changing-camera fixtures shows the candidate computes the correct
coordinate arguments; the audit mismatch remains visible. The base-bound
regression exception records this tradeoff without weakening acceptance.

Current source SHA-256:
`29966e39e8f1e9ed67ac197d8cc8c9cb8048a4457e51ec1138d3487b912d23d9`.
The function remains incomplete with analysis, compiler, and reference debt.

## Reproduction

From the repository root with the configured VC6 toolchain and optional
`unicorn==2.1.4` available:

```sh
uv run --with unicorn==2.1.4 python tools/match/evidence/laser-trig-rounding-2026-09-11/verify.py --out /tmp/laser-proof
uv run --with unicorn==2.1.4 python tools/match/evidence/laser-trig-rounding-2026-09-11/probe_controls.py --out /tmp/laser-controls
uv run --with unicorn==2.1.4 python tools/match/evidence/laser-trig-rounding-2026-09-11/replay_conventional.py --out /tmp/laser-conventional
uv run --with unicorn==2.1.4 python tools/match/evidence/conventional-corner-rounding-2026-09-11/replay_regressions.py --out /tmp/laser-regressions
```

Use the source named by the receipt when reproducing a historical result.
`verify.py --source PATH` accepts a historical or private candidate without
editing the canonical scratch.

## Python renderer follow-up

The Python renderer previously started the laser directly along the aim
direction, used a two-unit width with a one-screen-pixel minimum, kept the far
vertices red, and rounded alpha bytes upward. Its new corner helper preserves
the verified native start angle, 15/512-unit lengths, 2.2-unit width, and PC24
operation/store boundaries. Complete native corners are then projected with
the rewrite's per-axis viewport scale. The far vertices are black and alpha
bytes truncate like Grim2D. Existing alpha gating and both perk-ownership
modes remain in place.

[`verify_colors.py`](verify_colors.py) executes the original `grim_set_color`
and `grim_set_color_slot` bodies with the recorded native arguments.
[`native-colors.json`](native-colors.json) binds twelve palettes across six
alpha inputs and both control words. Its MSVCRT `_ftol` import is explicitly
modeled with the game's native converter, as in the earlier creature-color
proofs. Stack guards, callee-saved registers, and x87 state are checked.

[`verify_ports.py`](verify_ports.py) records the actual Python draw function
for **2,376 native fixtures**, **four viewport scales**, and **both
`preserve_bugs` modes**: **19,008 cases** agree on submitted vertex words and
packed vertex colors. Per-player ownership mode selects that player's
independently recorded native corner words. The historical Python function
from `07d412c426b343ee0328b543b63d73ce376509a0` fails geometry and color checks
for every case that submits a quad: 2,168 per scale with bug preservation,
2,176 per scale with per-player ownership. Texture, UV, blend, and draw counts
remain unchanged. See [`port-results.json`](port-results.json).

The CI test captures actual raylib submissions for **38 native fixtures at
four scales**, including every PC24 witness that rejected the old C++ trig
stores. Existing tests still exercise the ownership combinations. These
checks establish bounded CPU submission identity, not whole-frame, GPU,
simulation-state, or out-of-range-alpha equivalence. The C++ proof and
compiled source remain unchanged by the Python follow-up.

```sh
uv run --with unicorn==2.1.4 python tools/match/evidence/laser-trig-rounding-2026-09-11/verify_colors.py --out /tmp/laser-colors
uv run python tools/match/evidence/laser-trig-rounding-2026-09-11/verify_ports.py --out /tmp/laser-python
```
