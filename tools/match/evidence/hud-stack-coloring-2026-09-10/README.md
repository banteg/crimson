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
The model follows this observed allocation path: seed the parameter group;
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
