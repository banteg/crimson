# Highscore quest arms and operand ordering

A stock source witness now reproduces **1,437 continuous native bytes** from
score-row construction through the back-button update call. This includes the
quest unlock gate, its literal branch polarity, state writes, and all three
sound-call loads. The earlier row proof ended before the gate at 1,039 bytes.
The new witness also reproduces **1,356 bytes** of filter code, including both
label calculations. The preceding three-instruction filter setup still differs.

This is partial source evidence. Canonical source/configuration are unchanged,
coverage remains **804/810**, and both full-function exactness flags are false.
The witness is `quest-arm-direct`: 2,004/2,004 instructions, prefix 108,
references 623/0/2, source SHA
`bf9dce0fbce17274e1b7fcbe7905b967eff37b5b7cbc468b0d960e29174fc434`,
body SHA `21cf87610439508e50b4a8c16777d0534cec5af2646e61b5ec0021f1f332bb2d`.
Its 90.019960% alignment is not the acceptance criterion.

## Why a later quest edit changed the earlier row

The [previous study](../highscore-label-bitcopy-2026-09-22/README.md) found that
replacing the selected unlock-limit reference with separate comparisons changed
the row's allocation. The preserving C2 traces here locate the cause before
register allocation: a generated symbol number participates in the ordering
key for commutative expressions.

Pinned C2 `d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`
uses `0xf584` to sort operand chains. Its comparator `0xf6ae` compares the
32-bit key at operand `+0xc`, **unsigned descending**. The first observed sort
of each row addition is `0xd8ff -> 0xf584`; `0xd8ea` and `0xda8d` subsequently
sort the same expression. This precedes lowering at `0x2930f`/`0x29511` and
allocation through `0x32f7c`.

For this particular memory operand, `0xdbc5` computes the low key from its
`0x14c` addressing opcode, zero displacement, and its generated base symbol.
`0xdc61` contributes the generated symbol number shifted left by six; the
memory key shifts that result by eight and truncates to 16 bits. `0xda9a`
adds the single-leaf high word. The observed formula is:

```text
memory_key = 0x10000 | ((7 + (generated_base_id << 14)) & 0xffff)
prefix_key = 0x10360
```

The descriptor's kind is 3 and its definition link is null in every observed
base; the prefix is kind 4 with symbol number 27. These are checked descriptor
fields, not arena pointer hashes. The formula is scoped to this operand shape.

| Stock source | Base symbol number | Memory key | Prefix allocation ordinal / priority / register |
| --- | ---: | ---: | --- |
| Selected reference | `0xb2a` | `0x18007` | 6 / 106 / EBX |
| Separate comparisons, shared index | `0xb28` | `0x10007` | 1 / 274 / ESI |
| Named hardcore-limit reference | `0xb29` | `0x14007` | 6 / 106 / EBX |
| Separate index arms plus reference | `0xb28` | `0x10007` | 1 / 274 / ESI |
| Separate index arms, direct limits | `0xb27` | `0x1c007` | 6 / 106 / EBX |

When memory sorts first, lowering loads it into a temporary and adds the
prefix. The prefix has only two definitions and three source uses. When the
prefix sorts first, lowering copies it into the address result, then adds
memory. Allocation coalesces that copy: the prefix descriptor also becomes the
destination of all three additions and the source of their pushes. Its cost
rises from 20 to 44 and priority from 106 to 274, ahead of the row cursors.
The phase-4, phase-5, phase-10, and complete allocation observations check this
chain. It is not an unexplained allocation tie or a register-priority sweep.

Two diagnostic replays change only the three memory keys at the first and
final sorts: six writes per replay. Lowering and allocation switch in both
directions. No symbol number, pointer, operand link, instruction, register
eligibility answer, or source stream is changed. The forward intervention's
**entire COFF object**, except its timestamp, equals the stock named-reference
control. This connects the key decision to a source control; the intervention
itself receives no match credit.

## Recovering the native gate

A named value snapshot of the quest major component, or of both components,
produces the unchanged predicate object. Named references change the symbol
number and restore the row, but the shared-index form still loads hardcore
after the major component and retains the wrong branch polarity.

The final source puts the index expression in each hardcore/normal arm and
uses the native positive hardcore edge to the shared allowed block. C2 hoists
the common index calculation after the hardcore test, using AL for the test
and ECX for the index. Direct limit references give the row memory operand the
`0x1c007` key. This stock source recovers the gate, subsequent sound-load
registers, and back-button setup together. It is an emitted-code witness,
not a claim that the original author used these exact local names or gotos.

## Proof and limits

| Region | Native half-open range | Candidate range | Bytes / instructions | References / local branches |
| --- | --- | --- | ---: | ---: |
| Row, play gate, back-button update | `0x442b4d..0x4430ea` | `0x77d..0xd1a` | 1,437 / 359 | 134 / 39 |
| Filter core | `0x4433dc..0x443928` | `0x100b..0x1557` | 1,356 / 320 | 124 / 47 |
| Profile label, subset of filter core | `0x44340b..0x44342d` | `0x103a..0x105c` | 34 / 9 | 4 / 0 |
| Date label, subset of filter core | `0x4434f2..0x443514` | `0x1121..0x1143` | 34 / 9 | 4 / 0 |

`verify.py` checks every encoded byte after positional reference resolution.
Registers, stack displacements, branch bytes, and destinations are literal;
no binding or alias is added. All nine stock controls rebuild with checked
whole-COFF hashes and complete, conflict-free ESP propagation to balanced
returns. Six byte/reference corruptions are rejected.

`verify_compiler.py` runs five preserving captures/replays, checking whole COFF
identity and missing-stream rejection, then the two scoped interventions.
The observer identifies the prefix from its source definition, checks complete
operand chains and the generated base descriptor, and records all 170
allocation decisions. Three corrupted order records are rejected. Raw streams,
phase snapshots, objects, and source listings remain in the output directory;
receipts bind their hashes and the pinned compiler.

`verify_execution.py` checks **9,024 gate fixtures** against native execution
and an independent state-transition oracle: enabled/disabled play, signed mode
extremes, all 256 hardcore byte values, quest index boundaries, and independent
normal/full unlock limits. Ordered state writes and sound arguments agree,
stack balance and saved registers are preserved, and three semantic corruptions
are rejected. Sound calls are stubbed with all caller-saved integer registers
clobbered. This does not emulate audio, callbacks, complete widgets, full UI
execution, runtime FPU state, or unreachable/undefined source inputs. Row and
label byte regions agree with the earlier execution-proven code; this package
does not claim a new full row/label execution run.

Remaining mismatches include separator-Y store scheduling, saved return-state
loads/writes, the online-widget X-store order, the first three filter-setup
instructions, and later shared tails/zero copies. The two aligned reference
mismatches remain in saved-state restoration. The earlier 1,375-byte filter
region is **not** claimed for this source: only its 1,356-byte core is exact.
No canonical promotion or full match is claimed.

## Reproduce

From the repository root, using fresh output directories:

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-quest-ordering-2026-09-22/verify.py \
  --out /tmp/highscore-quest-ordering-regions
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-quest-ordering-2026-09-22/verify_compiler.py \
  --out /tmp/highscore-quest-ordering-compiler
uv run --offline --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/highscore-quest-ordering-2026-09-22/verify_execution.py \
  --out /tmp/highscore-quest-ordering-execution
```
