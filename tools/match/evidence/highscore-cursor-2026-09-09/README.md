# High-score submission cursor locality proof

The flags reference in `highscore_sync_worker` recovers the native field-based
cursor at `0x0042d31c`. Native advances `EDI` through the flags fields, tests
`[EDI]`, and forms the enclosing record with `lea esi, [edi-0x44]` only in the
submission arm. The former source materialized the record before testing its
copied flags and omitted that native `lea`.

The retained source raises normalized alignment from 92.571429% to 96.860133%,
extends the exact prefix from 130 to 340 instructions, and increases clean
references from 125 to 126. It remains **non-exact**, with 526/525 instructions
and `body_byte_exact=false`.

The instruction-count warning is real, but does not establish a new instruction
defect here. The former 525/525 total hid one missing instruction in the cursor
loop and an extra `mov edx, eax` at request cleanup. Recovering the former does
not introduce the latter. This is a manual, native-evidenced partial recovery;
the mutation winner filter and the instruction-count warning remain unchanged.

`verify.py` recompiles the pinned baseline and retained source with their
canonical configuration, generates object-equivalent listings, and checks:

- Before offsets `0x23c..0x2d6` become `0x23c..0x2d8`, matching the native loop.
- All 480 instructions outside that window preserve their encoded bytes, except
  two branches whose adjusted displacements reach the same relocated boundary.
- All 119 outside COFF relocation records preserve symbol, type, addend, data,
  and identity fields; only their locations shift with the longer loop.
- The first 340 native instructions have equal normalized instructions and
  clean, same-index reference proof. Neither version claims whole-body identity.

The native error-query register pairing at `0x0042d604` and request-close copy
at `0x0042d7d9` remain. The 23 complete request/query lifetime controls did not
remove them. They bound those source forms, not the function's matchability.

Reproduce from the repository root:

```sh
uv run --no-sync python tools/match/evidence/highscore-cursor-2026-09-09/verify.py \
  --out /private/tmp/crimson-highscore-cursor-verify
```

The verifier fails if the pinned original image, compiled bodies, outside bytes,
relocations, or prefix proof change. `comparison.json` records the checked hashes
and counts. The ordinary flags reversion and request/query controls are recorded
in the scratch's experiment ledger.
