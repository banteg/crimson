# HUD stack-coloring trace

The observer reproduces all nine stack-allocation groups of the canonical HUD
and checks the resulting offsets of all 32 local descriptors, including
compiler-generated temporaries. It records
66 compiler symbols and their directed interference sets. The observed object
is identical to the ordinary compiled object except for the COFF timestamp.
The HUD remains non-exact: 1,824 paired instructions, 393 clean references,
92.2149% normalized similarity, and encoded-body exactness false.

The existing [native stack-use map](../hud-lifetimes-2026-09-09/README.md)
identifies the differing native offsets. This package explains how the current
source receives its candidate offsets; it does not recover original source
names or prove that the remaining differences are unavoidable.

## Observation points

All addresses below are RVAs in the pinned VC6.5 `C2.DLL`:

- `33cde -> 4b617`: immediately before stack coloring, read the symbol order,
  sizes, use counts, and interference sets.
- `5840f -> 34032`: after coloring, read the same symbols' final descriptors.
- `9f220`: ordered symbol list; `9f218`: indexed symbol table;
  `9f204`: indexed interference sets; `9f20c`: symbol count.

A named symbol points to its source descriptor through its first word. The
stack offset is descriptor byte offset `0x0c`, not a word in the symbol itself.
For example, `panel_alpha` changes from frontend offset -12 to allocated offset
-44. The allocator pass is reached through `33b7b -> 33bf8 -> 4b617`.
The snapshot immediately before the coordinator calls `33b7b` still contains
the frontend offsets; the next coordinator snapshot contains the final offsets.

The loaded call-site hooks check both original call targets, save and restore
integer registers and flags, and leave compiler data untouched. On-disk
compiler binaries are unchanged. The verifier separately captures and replays
all four frontend streams, checks ordinary/captured/replayed/observed objects,
and rejects a withheld stream, a truncated trace, and a changed final offset.

## Verified candidate groups

The parameter has its own group at declaration offset +8. The eight local
groups, in allocation order, occupy 52 bytes:

| Offset | Size | Selected candidate values |
| --- | ---: | --- |
| -52 | 4 | banner fade, completion fade, health ratio, pulse speed, name X |
| -48 | 4 | slide X, name scale, stage scale, completion scale |
| -44 | 4 | panel alpha |
| -40 | 4 | HUD Y, bar X, text Y, health-fill alpha |
| -36 | 16 | banner alpha, popup fade, health-background alpha, XP progress color |
| -20 | 4 | bonus Y |
| -16 | 8 | quest-name length, bar position, constructor temporaries |
| -8 | 8 | main position, XP progress position |

Groups share storage only where the compiler's interference sets allow it.
The model follows this observed allocation path: scan the entire ordered list
to seed the parameter group;
visit the ordered locals; scan prior local groups backwards; reject conflicts
in either direction; permit at most a doubling in group size. Its offsets are
computed from the group sizes and checked against the captured descriptors.
It does not take the expected final offsets as inputs.

The compiler orders locals by increasing size and decreasing use count, with
updates during IR traversal affecting ties. `panel_alpha` and `hud_y` both
have five uses in this trace. The native uses -40 for the former and -44 for
the latter; their declaration order alone did not explain this difference.
The graph now permits checking source lifetime and expression-boundary
hypotheses directly. Changing a captured count, graph, or offset is not a
source recovery and must not be credited as a match.

## Reproduce

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/hud-stack-coloring-2026-09-10/verify.py \
  --out /private/tmp/hudgraph
```

`results.json` contains pointer-independent indexed symbols, all directed
interference sets, group membership, compiler/source hashes, and the full
capture verification receipt. Raw process pointers stay in the temporary
trace. The model deliberately asserts the observed single-parameter HUD path;
it is not a general VC6 stack allocator implementation.

## Parameter scan and source controls

The scalar-reuse control exposes a restriction in the initial model: the
parameter need not be the first sorted symbol. Sharing one float between
pulse speed, health ratio, and clock slide X creates a local with 19 counted
uses, ahead of the parameter with 18. C2 RVA `4b658` scans the whole list for
kind-5 parameters; its second pass at `4b6a1` skips those parameters while
processing locals. The model now follows these two passes.

The new observation verifies 64 symbols, nine groups, and all 30 local offsets,
with unchanged matching metrics. The shared float occupies -52, as did the
original pulse-speed and health-ratio locals. This source reuse changes the
compiler graph but does not recover the native stack layout.
`scalar-reuse-results.json` retains its capture and observation receipt.
Both it and the refreshed canonical receipt pass whole-object identity
checks excluding the COFF timestamp, and reject corrupted offsets, truncated
traces, and a missing frontend stream.

`source-controls.json` stores 81 exact source transformations and their measured
results. The initial 38 cover 10 local aggregates, eight scalar-reuse combinations,
eight whole-body helper boundaries, seven position-scope combinations, and five
clamp helpers. The additional 43 cover the coordinate and cursor controls below.
`verify_controls.py` checks the canonical source hash, applies checked line
edits, checks each reconstructed source hash, forces recompilation, and compares
instruction count, similarity, prefix, reference audit, and both exactness flags.
All 81 remain non-exact. Some whole-body helpers do not inline; those controls
also retain their reference-audit failures. These are bounded observations,
not semantic-equivalence proofs or evidence that other source forms cannot match.

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/hud-stack-coloring-2026-09-10/verify_controls.py \
  --out /private/tmp/hud-source-controls

UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/hud-stack-coloring-2026-09-10/verify.py \
  --source /private/tmp/hud-source-controls/scalar-reuse-graph/pulse_speed-health_ratio-slide_x/scratch.cpp \
  --out /private/tmp/hud-scalar-reuse
```

Use repeatable `--control FAMILY/NAME` arguments to reproduce selected controls.
The observer's optional `--source` uses the canonical HUD configuration and
records the alternate source in the capture receipt. `source-control-results.json`
retains the full 81-control verification receipt and compiler dependency hashes.

## Coordinate construction and bonus-cursor controls

These additional controls test source owners without changing the compiler,
reference aliases, or canonical scratch:

| Family | Controls | Observed result |
| --- | ---: | --- |
| Plain coordinate owners | 14 | Arrays and plain structs agree. Replacing the main position's construction/assignment removes 16 instructions; replacing the bar's removes nine; replacing both removes 25. Changing only the XP position is neutral. |
| Bonus cursor boundaries | 8 | Reference parameters, a reference local, and a one-field cursor struct are neutral. Enclosing the cursor and its uses in a smaller scope preserves 1,824 instructions and 393 clean references but lowers alignment to 91.008772%. |
| Shared bar field updates | 14 | Replacing selected constructor assignments with field stores, with current or extended position scope, produces 1,818–1,831 instructions. None improves the canonical result; two forms per scope restore the instruction count but lose alignment and mapped references. |
| Constructor argument owners | 7 | Borrowing the vector/color constructor's scalar arguments preserves instruction and reference counts. Results are neutral or lose one paired instruction's agreement. |

All 43 saved transformations reconstruct and compile successfully. No failed
compilation is counted as a source-recovery negative.

The plain-owner results distinguish the construction temporaries from the
coordinate storage: removing those temporaries also removes native operations,
while changing the XP storage alone leaves the mismatch intact. This narrows
these tested replacements. It does not prove the original source types or rule
out other lifetime boundaries. The canonical HUD remains 92.214912%, with
1,824/1,824 instructions, 393 clean references, and both exactness flags false.
