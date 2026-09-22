# High-score row induction recovery

The retained source recovers the native row loop's single entry, signed
buffer-end branch, separate Rush/Quest argument preparation, flags-based
record cursor, and prefix initialization before the empty-record test.
The function remains non-exact. Rank storage, several schedules, panel and
filter lifetimes, and the four existing reference mismatches remain open.

## The flags cursor has a source-level control

A preserving observation of pinned VC6 C2 identifies the relevant sequence:
`0x47c9a` introduces separate field induction values; the second `0x46a2f`
call from `0x45e0e` merges compatible values. Its helper `0x48e8b` counts a
linked use list, rather than consulting register-allocation priorities.
The two count callsites are `0x46ad2` and `0x46b56`.

For the indexed row source, this condition gives the flags induction value
an observed count of four, and the output cursor points at elapsed time:

```cpp
(flags & 5) != 0 && ((flags & 2) == 0 || (flags & 4) != 0)
```

Spelling the first mask as its two flag tests raises that count to five:

```cpp
((flags & 1) != 0 || (flags & 4) != 0)
    && ((flags & 2) == 0 || (flags & 4) != 0)
```

Stock VC6 now selects the flags cursor. Later optimization combines the first
two tests into native's `test al, 5`, so the final Boolean decision is unchanged.
The field offsets become native's elapsed `-0x24`, name `-0x44`, score `-0x20`,
and flags `0`, with stride `0x48`. This is a plausible source distinction with
a directly observed compiler effect; it does not identify the original text.

`verify_compiler.py` pins the source and compiler inputs, performs independent
normal/captured/replayed/observed whole-COFF checks for both sources, and checks
missing-stream rejection. It identifies the flags field from its frontend
operand, follows the generated induction owner, and checks the count caller's
owner and list argument. Exactly one watched count decision occurs per replay.
Arena addresses are meaningful only within a replay.

| Control | Actual count | Returned count | Result |
| --- | ---: | ---: | --- |
| Combined mask, preserving | 4 | 4 | Elapsed-time cursor |
| Combined mask, return same value | 4 | 4 | Identical whole COFF |
| Combined mask, scoped diagnostic | 4 | 5 | Flags cursor |
| Split mask, preserving | 5 | 5 | Flags cursor |

The last two rows produce **identical whole COFF objects except timestamps**.
The intervention changes only the selected helper return. It is not installed
in the compiler, scratch configuration, or native provider. The retained
candidate is built normally from the split-mask source.

The earlier broad trace was too large to retain as decoded JSON. Bounded
inspection of its completed capture located the pass; a fresh compact observer
and fresh replay receipts prove the count boundary. Raw artifacts stay in the
chosen output directory.

## Loop and lifetime controls

`controls.json` reconstructs all 22 source builds against commit `09841af5a`.
The indexed accesses and pretested loop are necessary context for this result;
a flags-based pointer declaration alone still compiles to a different cursor.
The source uses a signed row index and the real 100-element arrays.

Post-incrementing rank inside each formatting call merges Rush/Quest further
and does not explain native. Deriving rank from `score_count + 1` also does not
recover its native stack home. Capturing flags before the empty-record check
moves the byte load too early. These are bounded negative controls, not claims
that the lifetime families are exhausted.

## Execution and acceptance boundary

`verify_execution.py` executes native `0x442b4d..0x442c79`, the prior row loop,
and the retained row loop. Its 1,576 fixtures cover all 256 flag bytes, eight
mode values, signed division boundaries including `INT_MIN` and `-1`, and
empty/full tables with stops at 0, 1, 2, 99, and 100 rows. All agree on:

- Ordered modeled formatting calls, including destination, rank, signed value,
  name address and name bytes.
- Ordered game-memory writes by the row-loop instructions, final item pointers
  and every backing-buffer byte.
- Cleared sentinel row, published row count, updated Y coordinate, unchanged
  record table and balanced stack at region exit.

An independent oracle computes the flag policy, signed quotient, row bounds,
formatted text and expected buffer contents. Three instruction-corruption
controls are rejected: wrong prefix mask, unsigned division shift, and a
99-row bound. `sprintf` is modeled; the surrounding UI and real CRT are outside
this execution proof. This is not universal or whole-function equivalence.

Whole-function alignment changes from **78.499496% to 79.708689%**, gaining
97.049800 fuzzy-weighted bytes. Instructions change from 1,968 to 1,978 against
2,004 native; prefix stays 45 and the frame stays 132 bytes. References change
from **594/0/4 to 592/0/4**. The four mismatched native addresses remain
`0x442feb`, `0x442ff6`, `0x44324e`, and `0x443638`; the two fewer aligned references
are explicitly retained as a tradeoff. No reference aliases or acceptance rules
change. Both normalized and encoded exactness remain false.

Native still keeps prefix in EBX and rank in a stack home; the candidate keeps
prefix in ECX and rank in EBX. Favoring the flags cursor alone does not fix this,
as the scoped count intervention and the stock source produce the same body.
These value lifetimes are the next row constraint, independently of cursor bias.

## Reproduce

Use fresh output directories from the repository root:

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-row-induction-2026-09-22/controls.py \
  --out /tmp/highscore-row-controls
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-row-induction-2026-09-22/verify_compiler.py \
  --out /tmp/highscore-row-compiler
uv run --offline --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/highscore-row-induction-2026-09-22/verify_execution.py \
  --out /tmp/highscore-row-execution
```
