# Prefix lifetime across the row clear

Initializing `prefix_length` before `memset` recovers the native score-row
instruction sequence with stock VC6. The initializer still appears after the
clear in the final scheduled code, so final disassembly alone concealed the
source lifetime. Merely moving the declaration leaves the old body unchanged.
This is a source-controlled register-allocation result, not a whole-function
match. The canonical source is unchanged.

## Compiler cause and independent control

The preserving trace observes the prefix definition before allocation and the
inline clear's `0x111` operation. With the current source, the definition follows
the clear. Moving its initialization above the clear reverses that order.
The prefix is now live across the clear's EAX, ECX and EDI clobbers.

At C2 `0x32f7c`, called from `0x2fe5f`, register selection considers eligible
registers and costs. The eligibility test at `0x330c2` calls `0x251d`.
The observer identifies the prefix temporary by its two source definitions,
checks exactly one allocation, and records every eligibility result and the
chosen register. It uses no hard-coded arena pointer. The compiler is pinned
to SHA-256 `d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`.

| Source/control | Eligible registers | Chosen prefix register | Whole COFF |
| --- | --- | --- | --- |
| Initialize after clear | ECX, EDI, EBX | ECX | Current canonical |
| Same source, deny ECX once | EDI, EBX | EDI | Different diagnostic body |
| Same source, deny ECX and EDI once each | EBX | EBX | Equals stock before-clear source |
| Initialize before clear, preserving | EBX | EBX | Stock lifetime witness |

The two-register intervention produces **identical whole COFF output except
timestamps** to the stock source witness. It changes only two eligibility
returns for the selected prefix allocation. Installed compiler files, scratch
flags, reference aliases and acceptance rules are untouched.

Changing prefix eligibility alone reproduces all emitted effects of moving its
initializer: EBX prefix, spilled rank, call preparation and the changed stack
layout. The cost array is also unchanged at this decision. This isolates the
clear-crossing lifetime without attributing the result to a priority-only rank
heuristic. Declaration movement is independently byte-neutral.

Both source traces independently verify normal compile, frontend capture,
backend replay and observed replay as whole COFF objects. Missing-stream replay
is rejected. The supplemental observer records compact decisions rather than
repeated full-function snapshots. Raw descriptor addresses remain replay-local.

## What is recovered, and what is still different

Native `0x442b4d..0x442c79` and both retained source witnesses contain the same
95-instruction, 300-byte row sequence, apart from five stack-home bindings and
relocations. This includes EBX prefix, stack-held rank, flags-based record
cursor, distinct Rush/Quest argument preparation, signed division, all call
tails, row increments and the literal signed loop branch.

`region.py` resolves the references and checks every byte after translating
only explicit stack displacement fields. It propagates stack depth over the
region's CFG, rejects inconsistent joins, preserves literal branch bytes, and
requires a bijection for all five observed homes. These are diagnostic bindings,
not aliases or exact-match credit. Offsets below are relative to ESP at row entry.

| Row value | Native | Before-clear source | Combined source |
| --- | ---: | ---: | ---: |
| Position Y | 0x14 | 0x2c | 0x14 |
| Rank | 0x24 | 0x14 | 0x28 |
| Selected row | 0x34 | 0x20 | 0x2c |
| Published row count | 0x4c | 0x1c | 0x24 |
| Backing-buffer cursor | 0x28 | 0x18 | 0x54 |

The before-clear witness differs in 16 stack displacement bytes. The combined
witness differs in 14. Every other row byte agrees after audited relocations.
A corrupted literal branch and a swapped rank/buffer stack binding are rejected.

The full-function tradeoffs remain material:

| Source | Instructions/native | Local frame | Prefix | References ok/unresolved/mismatch | Alignment |
| --- | ---: | ---: | ---: | --- | ---: |
| Canonical | 1978/2004 | 132 | 45 | 592/0/4 | 79.708689% |
| Prefix before clear | 1986/2004 | 128 | 1 | 577/0/16 | 75.488722% |
| Combined native-dataflow controls | 2005/2004 | 132 | 43 | 604/0/6 | 83.512098% |

The combined source cumulatively adds the previously evidenced tooltip copy,
right-panel chained sum and copies, and label arithmetic `y + 114 - 14` and
`y + 70 - 14`. See the earlier
[residual decomposition](../highscore-residual-decomposition-2026-09-13/README.md).
Those controls restore the frame extent but do not settle its storage map or
other scheduling. The six reference mismatches pair music IDs, restored quest
stage fields, and filter label/coordinate setup. They remain visible. The higher
score is not a reason to promote this source without examining those regions.

`controls.json` reconstructs 11 builds against commit `6a4c8a2e5`. It separates
initialization placement from declaration scope, sharing the clear's zero, and
the three cumulative dataflow controls. They are bounded controls, not an
exhaustive search. The next source problem is the function's storage map and
remaining filter lifetimes; changing row division or argument spelling is no
longer necessary to obtain its native sequence.

## Execution proof and limits

`verify_execution.py` runs native, canonical, before-clear and combined row
regions for 1,576 fixtures. They agree with an independent oracle on formatting
arguments, rank, signed value, name, item pointers, every buffer byte, row count,
Y update, unchanged record table and balanced stack. Ordered game-memory writes
by row-loop instructions also agree. Fixtures cover all 256 flag bytes, eight
mode values, signed division boundaries, and row stops 0, 1, 2, 99 and 100.
Wrong prefix masking, unsigned shifting and a 99-row bound are rejected.

The formatter is modeled; its writes are checked through final buffers and do
not pass through the instruction-write hook. This proof covers only the row
region, not CRT internals, the surrounding UI, the combined panel/label edits,
or arbitrary full-function executions. Full-function ESP propagation reaches
all 2,004 native and 2,005 combined instructions with no join conflict and zero
return depth; that establishes stack balance, not semantic equivalence.

## Reproduce

From the repository root, use fresh output directories:

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-prefix-lifetime-2026-09-22/controls.py \
  --out /tmp/highscore-prefix-controls
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-prefix-lifetime-2026-09-22/verify_compiler.py \
  --out /tmp/highscore-prefix-compiler
uv run --offline --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/highscore-prefix-lifetime-2026-09-22/verify_execution.py \
  --out /tmp/highscore-prefix-execution
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-residual-decomposition-2026-09-13/frame_map.py \
  /tmp/highscore-prefix-controls/row-plus-widget-labels
```
