# Highscore label copies and stock source regions

A stock MSVC 6.5 source witness now reproduces two continuous native regions:
**1,039 bytes** of score-row and button code, and **1,375 bytes** of filter code.
Every byte agrees after resolving references. No stack displacement, register,
branch byte, or compiler decision is substituted. The filter region includes
native's post-version-call label-X load and both unspilled label expressions.

This is **partial source evidence, not another full-function match**. The
canonical source/configuration remain unchanged at 1,978/2,004 instructions,
prefix 45 and references 592/0/4. Both exactness flags remain false and coverage
remains 804/810. The witness is retained here, not selected as the canonical
scratch; its surrounding UI behavior is not covered by a full execution proof.

## What changed and why it matters

The [earlier storage study](../highscore-filter-storage-2026-09-22/README.md)
identified an extra float stack home for the explicit label-X snapshot. Moving
that scalar across the version call did not remove it. These controls change
how the copy is expressed, while retaining the existing cumulative row/panel
source and its filter arithmetic.

An aggregate copy of the two-float vector lowers X through a general register,
but also copies the unused Y member. Four-byte `memcpy` of the X member removes
that extra Y copy and the scalar's stack store/reload. This is a defined bit
copy, not an incompatible pointer cast. It is an emitted-code witness, not
evidence that the original source literally called `memcpy`.

Copying inside both branches of `game_is_full_version()` lets the compiler
place a single `mov edi, [right_panel.x]` immediately after the call, before
the `test al, al`. Merely introducing a named version result is insufficient:
the boolean form adds boolean materialization, and the byte form changes
distant allocation and shared call tails. An explicit two-component vector
constructor also differs from ordinary aggregate copy; copy construction and
copy assignment produce identical whole COFF objects apart from timestamps.

The cumulative witness additionally:

- Saves `filter_x` from the constructed online widget before its update call.
- Uses the literal eight-byte scrollbar clear `memset(column_offsets, 0, 8)`.
  This removes the pointer loop and, in this combination, restores native's
  EDX zero followed by the later EBP zero. Direct element assignments do not
  produce the same surrounding code. The control name `sdk-clear` is retained
  from the experiment; this package proves native output, not SDK provenance.
- Initializes the player-item array immediately before the player-list static
  guard. This agrees with native's initialization stage and storage, unlike
  the earlier control that moved the array before the date widget.

The Y expression's existing address-escape control is still present: the final
game-mode widget uses the right-panel object's address. Combined with these X
copies, the profile/date expressions recompute their sums without an extra
float32 store. Native `(Y + 114) - 14` and `(Y + 70) - 14` are preserved.
The earlier [float counterexamples](../highscore-float-reuse-2026-09-22/README.md)
explain why replacing these with folded constants or rounded intermediate
stores is not an acceptable recovery.

## Encoded-byte and execution checks

`native-boundaries-gate-0-items-1` is the verified witness. Its source SHA is
`d792e8f3b99ba797cb1a90683342a31667d2c5818e6278294e87d54bb970d9c9`, and its
body SHA is `e2ba4046f4c401684fc2277a1f8d68d34ae48dc31acb7a47458827982a256075`.
It has 2,004/2,004 instructions, prefix 108, references 626/0/4 and 89.820359%
fuzzy alignment; both full-function exactness flags are false.

| Region | Native half-open range | Instructions | Bytes | Audited references | Local branches |
| --- | --- | ---: | ---: | ---: | ---: |
| Score row through play-button update | `0x442b4d..0x442f5c` | 270 | 1,039 | 90 | 29 |
| Filters after date-list construction | `0x4433c9..0x443928` | 323 | 1,375 | 126 | 47 |
| Profile label arguments | `0x44340b..0x44342d` | 9 | 34 | 4 | 0 |
| Date label arguments | `0x4434f2..0x443514` | 9 | 34 | 4 | 0 |

The two label windows are subsets of the filter region, not additional bytes.
The verifier checks instruction boundaries, positional reference meaning,
every relocation, all encoded bytes, and every branch's destination. All
branches remain within the audited region or reach its end. Branch bytes and
stack displacements are literal comparisons. Six corruption controls reject a
changed row branch, changed stack displacement, wrong reference owner, omitted
relocation, truncated window, and substitution of the date label for the
profile label despite their identical normalized instruction text.

All 25 stock sources rebuild with `/O2 /GB /W3 /GR-`; every whole-COFF hash is
checked after clearing only its timestamp. The canonical control is included.
Static ESP propagation reaches every instruction with no conflicting joins
and balanced returns for every build. The input chain and metrics are in
`controls.json`; `results.json` is the byte/frame receipt.

`execution-results.json` covers narrower executable windows:

- **1,576 row fixtures** compare native, the witness and an independent output
  oracle across all 256 flag bytes, game modes, signed division boundaries and
  row counts 0, 1, 2, 99 and 100. Native/witness comparison includes ordered
  writes, item and buffer bytes, formatting arguments, stack balance and
  unchanged input records. `sprintf` is modeled as in the earlier row proof.
- **19,800 label fixtures** cover both labels, 275 finite Y bit patterns,
  all three x87 precisions and four rounding modes, and three raw X patterns
  including negative zero and a quiet-NaN payload. An exact-rational oracle
  models each arithmetic rounding and the final float32 store. Execution stops
  before drawing; it checks argument bits, stack balance and an empty x87 stack.
- Five execution corruptions reject the wrong prefix mask, unsigned division,
  a 99-row limit, and a wrong addition constant in either label.

The complete filter widgets, callbacks, static constructors and surrounding UI
paths are not emulated. Finite label tests do not establish runtime FPU state,
reachability, exceptional-Y behavior or full-function semantic equivalence.

## Remaining controls and stop rules

The 25 sources include three baselines and 22 new forms. Negative controls
remain alongside the witness:

- An online-widget assignment inside the constructor argument is whole-COFF
  identical to the separate pre-constructor assignment. Its higher 93.290097%
  alignment has 2,005 instructions, prefix 43 and references 601/0/6, and moves
  stack homes. It is not selected based on that score.
- Replacing the quest-unlock reference selection with separate hardcore/normal
  comparisons restores that local control structure but changes the earlier
  row's register allocation and later shared tails. The combined control has
  only 1,990 instructions. A conditional-expression predicate instead
  materializes boolean values. Neither solves the complete native constraint.
- Chained explicit widget member assignments differ from the constructor
  forms; changing which assignment receives the value first is not a general
  way to recover the native storage layout.

Outside the audited regions, the witness still has the separator-Y store's
wrong schedule, the quest gate's selected-pointer form, changed music-load and
return-state copy registers, the online X-store order, and later branch/zero
differences. The four matcher reference mismatches are retained honestly;
they occur where its instruction alignment pairs different music/quest
references. Region proofs do not waive them.

The next problem is controlling those lifetimes and branch structures while
preserving the verified regions. No allocation-order cause is claimed for the
distant changes from the quest predicate; that requires a preserving compiler
trace before further source tuning.

## Reproduce

From the repository root, using fresh output directories:

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-label-bitcopy-2026-09-22/verify.py \
  --out /tmp/highscore-label-bitcopy-proof
uv run --offline --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/highscore-label-bitcopy-2026-09-22/verify_execution.py \
  --out /tmp/highscore-label-bitcopy-execution
```

The execution command uses the existing Unicorn cache. Without a cached copy,
omit `--offline` to allow dependency resolution. `controls.py --out <fresh-dir>`
also rebuilds just the stock source controls. Generated sources, COFF objects
and annotated disassembly stay in the output directories. Compiler patches,
reference aliases and acceptance rules are unchanged.
