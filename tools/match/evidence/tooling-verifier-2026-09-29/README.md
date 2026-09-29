# Matching verifier fixes, 2026-09-29

Baseline: `4100e68dff1a2c256f035811f5bc8733842baa5a`.

The regression tests in `tests/test_match_verification_regressions.py` cover
four confirmed bugs:

- Indexed table accesses and address-taking instructions could use one scalar
  value as content proof. Arrays `[1, 2]` and `[1, 3]` were accepted even though
  loading element one returned different values. Content proof now requires a
  direct scalar read; indexed accesses, pointers, writes, and other segments
  require a proven owner.
- Aggregate-copy proof ignored accesses that started outside a copied range
  but overlapped it. The proof now checks full access widths and expires on
  overlaps, unknown memory accesses, direction changes, and control-flow joins.
- Raw suffix trimming could remove `cc` or `90` from actual instructions. For
  example, different short-jump displacements became identical undecodable
  opcode bytes. Extraction now retains the bytes and excludes padding only
  after decoding and checking branch destinations.
- Angle-bracket includes were absent from dependency fingerprints, so editing
  a transitive header could reuse an old compiler object. Both cache and probe
  fingerprints now discover quoted and angle-bracket includes in compiler
  search order. The regression runs the real MSVC/Wibo compiler twice.

The padding fix initially exposed seven alignment NOPs in
`grim_jaz_jpeg_error_exit`. Its 41-byte body remains exact. Padding after the
compiler's unreachable cleanup is excluded only for a resolved native
`longjmp` import and when no local branch enters that tail. Returning calls,
local lookalikes, branches into cleanup or padding, and unknown indirect jumps
retain their bytes.

## Scores

`score-comparison.json` records the full before/after measures and affected
functions. The canonical baseline was independently rebuilt before editing.
The historical baseline uses the original verifier on the same sources,
build-specific compilers, and images, with status-cache reads and writes
disabled. Diagnostic baseline evidence was not written into repository
manifests.

| Published measure | Before | After |
| --- | ---: | ---: |
| 1.9.93 game and engine | 100% | 100% |
| 1.9.93 overall exact code | 64.0942347% | 64.0942347% |
| 1.9.93 matched data | 63.1485423% | 63.1485423% |
| 1.9.8 overall exact code | 16.0397842% | 15.2845431% |
| 1.9.8 game and engine | 10.9728102% | 10.9704250% |

In canonical full-scope scratch verification, four D3DX archive scratches move
from `match` to `audit`: `d3dx_png_format_buffer`,
`d3dx_jpeg_decode_mcu_huff`, `d3dx_jpeg_decode_mcu_dc_first`, and
`d3dx_jpeg_decode_mcu_ac_first`. All normalized instruction ratios remain 100%,
but ten indexed-table references are unresolved across 2,170 bytes. Archive
scratch candidates were not credited as recovered source in the public report.
The remaining 2,420 scratches are exact; no canonical instruction score falls.

For 1.9.8, six source candidates retain matching normalized instructions but
lose exact reference proof: `d3dx_jpeg_alloc_small`, `inflate_blocks`,
`grim_jpeg_alloc_small`, `grim_jpeg_decode_mcu_huff`,
`grim_jpeg_decode_mcu_dc_first`, and `grim_jpeg_decode_mcu_ac_first`.
They lose 5,040 bytes of exact credit and expose fourteen unresolved references.
Decoded extent accounting changes the historical code denominator by a net
23 bytes. The game category still has 428 exact functions and 34,319 matched
bytes; its denominator grows by 68 bytes.

## Validation

- 611 matching and native tests pass; seven optional external-alignment tests
  skip because their tools are not configured.
- All 44 added regression cases pass.
- Both native images link and their saved receipts validate as current, with
  game-owned closure intact.
- The native-manifest regression comparison against the baseline passes.
- Both published reports refresh and validate against their saved inputs.
- Ruff, type checking, documentation checks, resolved-name audit, and
  `git diff --check` pass.

No reference aliases or regression waivers were added to recover lost credit.
