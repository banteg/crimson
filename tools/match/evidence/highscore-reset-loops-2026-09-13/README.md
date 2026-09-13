# Highscore pool reset loops

The five pool resets at native `0x004430fd..0x00443158` use signed `jl`
backedges. Ordinary signed index loops reproduce them. The previous pointer
comparisons emitted unsigned `jb` backedges.

`verify.py` compiles the pinned baseline and current source with the canonical
profile. Exactly five bytes change, each `72` to `7c`; the other 7,889 encoded
bytes and every relocation remain identical. The complete 25-instruction reset
window agrees with native after accounting for its function-relative position,
including all ten positional pool/start and end references and all five branch
destinations. This verifies a local recovery, not a whole-function match.

The loops clear 16 bonus IDs and the active flags of 96 projectiles, 384 sprite
effects, 64 secondary projectiles, and 384 creatures. Every native pool and end
address is below `0x80000000`, so the signed and unsigned comparisons traverse
the same bounded ranges. The modern port behavior does not change.

Whole-function metrics remain 78.429398%, 1,969/2,004 instructions, prefix 45,
and 594/0/4 references. The unchanged score reflects differing branch target
offsets elsewhere in this still non-exact function.

Replay from the repository root:

```sh
uv run --no-sync python tools/match/evidence/highscore-reset-loops-2026-09-13/verify.py \
  --out /private/tmp/highscore-reset-loop-proof
```
