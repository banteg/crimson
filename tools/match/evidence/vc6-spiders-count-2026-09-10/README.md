# Spiders Inc. count lowering

The retained source and a scalar-count control diverge before local register
allocation. This observer identifies that boundary without changing compiler
decisions. Neither source is an exact match.

The canonical source initializes `wave_count` through the first entry's count
field. The control computes the scalar at the same source position, then stores
it after that entry's trigger time. The verifier generates this control from the
pinned canonical source; it does not install it as the scratch.

Four snapshots follow the original division and addition node identities:

| Observation | Canonical early field assignment | Late scalar assignment |
| --- | --- | --- |
| Before C2+0x281cd | Addition destination operand kind 2 | Addition destination operand kind 1 |
| Before C2+0x2930f | Addition opcode 0x16d | Addition opcode 0x16d |
| After C2+0x2930f | LEA, opcode 0x12 | ADD, opcode 0x2d |
| Before C2+0x336f4 | Division and addition have distinct destination storage owners | Division and addition share a destination storage owner |

This rules out attributing the whole difference to the later physical-register
choice. It does not identify the original source, prove the operand-kind
difference is the sole cause, or establish that any source family is exhausted.
The first snapshot is before the named pass, not the beginning of C2 execution.

Run from the repository root:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-spiders-count-2026-09-10/verify.py \
  --out /private/tmp/c2spiders-count-proof
```

For each source, the verifier checks normal, captured, replayed, and observed
whole-COFF equality with only the COFF timestamp excluded. It also requires the
missing-stream negative control to fail and the observed match metrics to equal
the normal build. The observer preserves registers and flags, validates each
hook's original call target, and reads the instruction list and operands.

The recorded canonical result is 96.1905%, 105/105 instructions, with seven
clean aligned references. The scalar control is 75.8294%, 106/105 instructions,
also with seven clean aligned references. Both normalized exactness and
relocation-aware encoded-body exactness are false. New source matches: **0**.
