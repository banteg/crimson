# highscore_rank_index

Binary Ninja shows three straight insertion scans over the 0x48-byte high-score
records:

- Rush returns the first row whose elapsed value is below the active value.
- Quest returns the first row whose elapsed value is above the active value.
- Other modes return the first row whose score is below the active score.

The recovered source has the native 51-instruction control-flow shape and all
four references resolve. MSVC assigns the loop bound to EDX and the record
cursor to ECX, while the native body makes the opposite allocation in all three
loops. The source intentionally remains a WIP instead of forcing registers with
artificial aliases or byte-shaped control flow.

An explicit record cursor compiles identically. Per-arm count snapshots instead
coalesce the later loads and regress to 50 instructions. The VC6.0 and VC6.6
backends retain the same register swap; VC6.5pp and VC7.0 hoist the count and
diverge further. There is no remaining natural source or compiler-profile lead.

## Recovery classification audit

Live Binary Ninja HLIL confirms the three mode-select branches, signed
comparisons, 0x48-byte scans, and count fallbacks. Candidate and native each
have 51 instructions and all four references resolve. The one whole-body
region is the same record-cursor/loop-bound register swap repeated in all three
scans, so recovery is `semantic-complete` with a `compiler` residual.

## Fresh native and profile audit

Live Binary Ninja disassembly at `0x0043b520..0x0043b5a4` confirms one
consistent native allocation across all three scans: `EAX` is the index,
`ECX` is the cached count, `EDX` is the record-field cursor, and `ESI` is the
active value. Rush and the default score scan return on signed `jg`; Quest
returns on signed `jl`. The cursor advances by the exact 0x48-byte record
width. The candidate has the same instructions, branches, references, and
layout, but assigns count to `EDX` and cursor to `ECX`.

Binary Ninja types `0x00487040` as `highscore_active_record`; the native active
loads at `0x00487060` and `0x00487064` are its elapsed and score fields, with
standalone symbols at the same subobject addresses. Rewriting the source
through `highscore_active_record.survival_elapsed_ms` and `.score_xp` compiles
byte-identically, confirming that the alias presentation is not hidden
semantic debt or the cause of the register swap.

A fresh profile matrix leaves VC6.0, VC6.5, and VC6.6 tied at 58.8235%,
78.2353/133 fuzzy-weighted bytes, 51/51 instructions, a four-instruction
prefix, and `4/0/0` references. `/G5`, `/Oy-`, `/Ot`, and `/TP` are neutral.
VC6.5 Processor Pack falls to 42.00%, VC7 to 39.60%, `/G6` to 56.86%, and
size or unoptimized profiles are substantially worse.

## Recorded source-shape sweeps

Three bounded specs record the remaining natural source hypotheses:

- `register-allocation-mutations.json`
  (`720820af7ce6974bb4cb0f4a126fc47202b6b4ce958136667d9bec5f6f35e932`)
  tests nine whole-scan shapes. `while` loops and active-record field spelling
  are byte-identical; reversed loop operands lose 7.8235 fuzzy-weighted bytes.
  Function-scoped count/cursor forms coalesce one instruction and lose
  17.6610 bytes. Four exploratory block-local variants fail under the
  scratch's C89 compilation because their final-arm declarations follow
  statements; the corrected forms are covered by the next spec.
- `block-count-cursor-mutations.json`
  (`1df905125e26ac67c3b53e580b276d756972ad72fa70b621349f8ab013a9b846`)
  evaluates all 4/4 valid per-arm count/cursor order, `while`, and
  active-record interactions. Every form emits 50 instructions, scores
  45.5446%, and loses 17.6610 fuzzy-weighted bytes.
- `comparison-shape-mutations.json`
  (`da51fcae800fea4626fa5651580d13d922b1a9725ffbb32fa4c9dac5fd1f4d08`)
  evaluates all 5/5 record/value-local, active-local, and reversed-comparison
  forms. Per-iteration record and value locals are byte-identical. The other
  three lose 7.8235 to 28.6863 fuzzy-weighted bytes and can reduce aligned
  reference coverage.

No valid variant improves the baseline, so `scratch.c` remains unchanged.
Artificial register hints or byte-shaped aliases were not tested: they would
encode the compiler residual rather than recover additional program semantics.

## Interior field-cursor bound (2026-08-11)

Live Binary Ninja renders each native scan as an `int32_t *` interior cursor:
the Rush and Quest arms start at `survival_elapsed_ms`, the default arm starts
at `score_xp`, and all advance by 18 words. The complete 26/26 sweep in
`field-cursor-mutations.json` tests signed and unsigned interior pointers in
each arm, every pair, and all three-arm interactions.

Every variant is byte-identical to the 58.82%, 51/51-instruction baseline with
`4/0/0` references. Explicitly recovering the native pointer presentation does
not change VC6's `ECX`/`EDX` allocation, so the indexed source remains the
smaller canonical form. The spec SHA-256 is
`1553d84e3911a541e69a64512cd0d68db8b5daaeedacab9ce4bfa51a4939a9e2`.

## Indexed count-only snapshot bound (2026-08-15)

The earlier block-local sweep paired a cached count with an explicit record
cursor, so it did not isolate whether count ownership alone could recover the
native `ECX` allocation while leaving the indexed table expression intact.
`count-snapshot-only-mutations.json` tests that missing source shape in all
three mode arms against the current source epoch.

The complete one-variant sweep regresses from 51 to 50 instructions and from
78.2353 to 60.5743 fuzzy-weighted bytes, while references remain clean at
`4/0/0`. VC6 coalesces a later count load without changing the underlying
count/cursor register choice. No source change is retained. The spec SHA-256 is
`607c71b0269e0e063863c66eb64eeec1fbbb2eff97c72d5e802313689e22e27e`.

## Exact shared fallback recovery (2026-09-04)

The earlier register-allocation residual conclusion is superseded. The three
mode-specific scans now share their `return highscore_table_count` fallback,
while each successful comparison still returns its index immediately. This
ordinary `if` / `else if` / `else` structure recovers the native allocation
throughout all three loops without changing their signed comparisons or
negative/zero-count behavior. No table or count writes occur during the scans.

The result is **100% exact**, 51/51 instructions, a full 51-instruction prefix,
and references **10/0/0**, versus 58.8235%, prefix 4, and 4/0/0 previously.
`shared-rank-fallback-mutations.json` records all nine control-flow variants.
Sharing only the fallback is exact in both structured and labeled forms;
sharing the successful-index return as well reaches only 88.2353%, and sharing
only the successful return regresses. The structured fallback is retained.
No register hints, compiler changes, reference masks, or scope changes are used.
