# Rebrew near-diag comparison

**Keep Crimson's diagnostics and C2 tracing as the primary tools.** On this
small sample, Rebrew's unmodified near-diag core added no new causal explanation.
Its compact classification and mutation suggestions are convenient, but some
labels are too permissive to use as matching or equivalence evidence.

Rebrew is pinned to `e3eeaf452c319bbf26db87009d339e146e6c1f86` from
[the upstream repository](https://github.com/maci0/rebrew). This is a test of
`rebrew.near_diag.analyze`, the core used by near-diag, including its frame and
CFG diagnostics. It does not benchmark the full CLI/project import, toolchain
manager, mutation search, or symbolic prover.

## Frozen functions

`export.py` recompiles frozen copies of three current scratches. It saves the
original compiler object and both original byte arrays, then materializes
candidate references using Crimson's independently resolved names/addresses,
unique native content identities, or intra-object targets. It does not pair
instructions to choose addresses and passes **no relocation mask** to Rebrew.
Every field rewrite is recorded. All three cases resolve every relocation;
the exact control's materialized bytes equal the native bytes. This adapter
measures classification independently of Rebrew's project/catalog integration.

| Function | Crimson baseline | Rebrew verdict | Added explanation |
| --- | --- | --- | --- |
| `statistics_update_check_worker` | Exact encoded body; 120 clean references | MATCH | Exact control passes |
| `quest_spawn_timeline_update` | 91.2281%; 13 clean references | STRUCTURAL, 52% of delta | First mismatch is a shifted conditional branch destination; does not explain the pointer store or zero allocation |
| `projectile_render` | 62.3580%; see saved reference audit | STRUCTURAL, 93% of delta | First mismatch is the already-known prologue reservation, `0x19c` versus `0x184` |

The renderer's Rebrew frame report says `0xa78` versus `0xa58`. Its implementation
tracks stack operations linearly through the entire listing, without CFG path
separation or callee-pop accounting. Those numbers should not be treated as the
prologue reservation or a validated maximum runtime stack depth. Crimson reports
the explicit prologue allocation and labels its stack/lifetime correspondences
as diagnostic.

The overall byte percentages are not comparable to Crimson's normalized
instruction ratio and do not establish matching progress. Direct branch
destination differences also include layout consequences.

## Positive and negative controls

- Identical bytes: MATCH. All three native self-comparisons also pass.
- `89 d8` versus `8b c3` (`mov eax, ebx`): correctly identified as alternate
  encoding. An explicit encoding category is a useful reporting idea.
- `xor eax, eax; ret` versus `mov eax, 1; ret`: **EQUIVALENT**, although the
  returned constants differ. `classify_pair` accepts a mnemonic family without
  checking the operands' semantics.
- `mov eax, ebx; ret` versus `mov ecx, ebx; ret`: **EFFECTIVE (matches modulo
  register allocation)**, although the ABI return register is no longer written.
  For initial EAX=0, EBX=1 these return different values. Register stripping does
  not establish a consistent value mapping or preserve observable registers.
- Changed immediate, call destination, and stack slot: STRUCTURAL as expected.
- A call to the same address shifted by one byte is labeled ENCODING-ONLY along
  with its differently encoded NOP. Its call displacement changed because of
  location, not opcode selection. The encoding category needs a relative-operand
  check before it can diagnose compiler opcode preferences.

These are heuristic-label failures, not claims about Rebrew's separate prover.
The generic suggestions to change pointer arithmetic, declarations, or loop
forms do not add to Crimson's existing bounded source-mutation workflow.

## Reproduction

Use the Crimson environment for export and an isolated environment containing
Rebrew's diagnostic dependencies for analysis. Do not install Rebrew into
Crimson's environment. Dependency versions and upstream revision are saved in
[results.json](results.json).

```sh
uv run python tools/match/evidence/rebrew-comparison-2026-09-13/export.py \
  --out /private/tmp/rebrew-comparison/cases
PYTHONPATH=/path/to/rebrew/src /path/to/rebrew-env/bin/python \
  tools/match/evidence/rebrew-comparison-2026-09-13/analyze.py \
  --rebrew /path/to/rebrew --cases /private/tmp/rebrew-comparison/cases
```

The saved result includes inputs, per-relocation transformations, native checks,
all controls, complete Rebrew diagnoses, and compact Crimson diagnostic summaries.
The temporary environment and upstream checkout are not runtime dependencies.
No source candidate, compiler flag, or matching acceptance rule was changed.
