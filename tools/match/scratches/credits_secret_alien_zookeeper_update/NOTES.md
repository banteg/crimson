# credits_secret_alien_zookeeper_update

Native target: `crimsonland.exe` at `0x0040f4f0`, 2,612 bytes and 638
normalized instructions.

This scratch recovers the complete frame callback for the credits-secret
AlienZooKeeper minigame:

- positions and draws the title, subtitle, score, board, and countdown bar;
- advances the animation clock and expires the countdown with the native
  death sound;
- draws the selected cell and all visible members of the 6x6 board;
- accepts two arbitrary cell selections, swaps them, finds the first
  horizontal or vertical triple, marks its three members as `-3`, increments
  the score, plays the bonus sound, and adds two seconds;
- replaces only `-1` cells with random values during the per-frame fill pass;
- rerolls the whole board on Reset until it contains no immediate match, then
  clears the selection and score and starts a 9,600 ms countdown; and
- queues the statistics menu when Back is activated.

The function-local Reset and Back buttons and their two initialization guards
are represented as native-style local statics. The data labels at
`credits_secret_board + 4`, `+8`, `+24`, and `+48` are overlapping aliases of
board cells 1, 2, 6, and 12, not four independent match-mask arrays.

Native behavior intentionally retained:

- opening the panel does not initialize or reroll the process-lifetime board;
- the two swapped cells need not be adjacent;
- only the first match reported by `credits_secret_match3_find` is cleared;
- cleared value `-3` is not refilled by the ordinary `-1` fill pass; and
- this callback does not mutate any unlock flag.

Best verified MSVC 6.5 result:

- 83.86% matched;
- exact 638/638 normalized instruction count;
- exact `0x54` stack frame;
- 15-instruction exact prefix; and
- 154 resolved references, with no missing or extra references.

MSVC 6.6 produced the same useful shape during compiler-profile testing.
MSVC 6.5 Processor Pack regressed substantially. The remaining mismatch
regions are dominated by register choice, spill-slot assignment, and nearby
instruction scheduling inside the nested drawing loops; the recovered control
flow, globals, calls, constants, and game behavior are complete.

The source uses normal C++ vector operators and direct global updates because
those reproduce native x87 and register scheduling best. It contains no
volatile coercions, dummy calls, dead arithmetic, inline assembly, fabricated
reference aliases, or other fakematching devices.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja output covers the timer, drawing loop, arbitrary-cell
swap, first-match clearing, score/time award, reset reroll, and Back route;
IDA and Ghidra corroborate the same seven-callee surface. Candidate and native
remain exactly 638 instructions with the exact `0x54` frame and a clean
`154/0/0` reference audit. A temporary scalar-component rewrite of the
initial chained panel expression was rejected: it fell from 83.70% to 76.45%,
reduced the prefix from 15 to 3, and changed the audit to `147/0/4`.

## Selected-highlight counter sweep (2026-07-27)

A fresh pass selected the largest coherent mismatch region at
`0x0040f83d..0x0040f94c`. Live Binary Ninja shows the selected-cell highlight
using a promoted linear index, a promoted column counter, and one spilled row
counter, then forming `(column, row) * 32 + board_position + (4, 4)` before
drawing the 24-pixel fill and outline. The source contains that exact loop and
coordinate behavior; only legal spill-slot coloring and nearby x87 scheduling
differ.

The recorded schema-1 `selected-highlight-counter-lifetimes` sweep tested all
5/5 planned declaration, split-initialization, and outer-column lifetime
forms. Its spec SHA-256 is
`fed25a4f87c06fb05a82d8fec4d69106dad07e223c919dead099b8b78215c318`.
Every single is byte-identical to the baseline:
`2186.219435736677/2612` weighted bytes (`83.69905956112853%`), gap
`425.78056426332296`, 638/638 instructions, prefix 15, and `153/0/0`
references. The record has `best_improves=false`, so no interaction sweep or
source change is justified. The unchanged source SHA-256 is
`83befaeb028305ccdf28f767bb1f82a00a9bbec765dcfb060c4e5d5c99581c4f`.

## Mutation-harness wave (2026-07-27)

Live Binary Ninja target `3023:2:9499448411019345244` confirms the native
function at `0x0040f4f0` is 2,612 bytes. The entry computes the board Y value
with an explicit add followed by a distinct store at
`0x0040f56d..0x0040f57b`; HLIL exposes that stored result as `var_2c_1`.
Representing it as the ordinary named intermediate `board_y` is therefore
native-evidenced source, not an artificial dependency.

The complete recorded `initial-layout-mutations.json` sweep evaluated all
80/80 single-site and two-site variants. Its spec SHA-256 is
`a6577a2c7e88830ad020e307297b2f201c434ae70ec55e2f18408500e642c3b0`.
The named Y intermediate was the retained source shape: weighted bytes rose
from `2186.219435736677` to `2190.3134796238246`, ratio from
`83.69905956112853%` to `83.85579937304075%`, and aligned references from
`153/0/0` to `154/0/0`. It preserves the exact 638-instruction count,
15-instruction prefix, and first mismatch at normalized offset 61. The fuzzy
gap fell by `4.0940438871475635` bytes, from `425.78056426332296` to
`421.6865203761754`. The retained source SHA-256 is
`812e79e1415800f212ad810df381d461d5ddb2039b04bcdad49e05e7a6975549`.

Two follow-up plans recorded complete negative evidence from the improved
baseline:

- `board-loop-register-mutations.json`, SHA-256
  `3606c6bb0c1a46fca9dfbb91f6ccb3e43bd7cf8b0812215050265360af4ed4cf`,
  evaluated all 57/57 declaration-order, pointer/value-load, and two-site
  combinations. Every variant was byte-identical to the improved baseline.
- `timer-layout-mutations.json`, SHA-256
  `ae95837566f483edf6d9c01c3326edd42ffb222768639113e6a55620a80c23ea`,
  evaluated all 29/29 width/position lifetime combinations. The ordinary
  forms were byte-identical; split default construction regressed to 642
  instructions and was rejected.

The compiler sweep covered all five installed backends. MSVC 6.5 and 6.6 tie
for best; 6.0, the 6.5 Processor Pack, and 7.0 regress. An additional
11-profile VC6.5 flag matrix found `/GB`, `/G5`, and `/Ot` byte-identical.
`/Ox` keeps the fuzzy ratio but introduces six unresolved references, while
`/Oi-`, `/Oy-`, `/G6`, `/Op`, `/Ob0`, `/Os`, and `/O1` regress. No compiler
or flag override is justified.

## Panel/board stack-coloring boundary (2026-08-06)

A focused comparison of the persisted native executable disassembly and the
current candidate object isolates the first broad divergence to stack-slot
coloring for the short-lived panel expression and the long-lived board
position. Both objects retain the exact `0x54` frame and 638 instructions;
the same x87 values are stored and copied, but VC6 assigns the two vector
pairs in the opposite slots from native.

`panel-board-lifetime-mutations.json` tests all five ordinary declaration and
construction boundaries suggested by that evidence: declaring the board
before the panel, splitting both declarations, component copying, and direct
board construction with or without copy-initialization. The first two are
byte-identical to the 83.86%, 638/638, `154/0/0` baseline. Component and
direct construction remove four native instructions, move the first mismatch
earlier, and introduce reference debt, so none is retained. The complete spec
SHA-256 is
`4924d8330935140e46d8ee7b3890bde13f6054bc6b0d685e7a54a9457cb5dbbb`.

`panel-operator-shape-mutations.json` then crosses four normal
`operator+` return shapes with four panel-expression forms, including named
intermediates, a named addend, right association, and compound addition. All
24/24 single and paired variants were evaluated. The neutral forms preserve
the same stack coloring; the other forms regress instruction, prefix, or
reference fidelity. The complete spec SHA-256 is
`1ef4bd2817a24a3305bdb8e0942c15ea25f3bc39400277919a26c371278eb796`.

These negative results close the natural source-lifetime explanation for the
first mismatch without volatile state, padding, or forced dependencies. The
canonical source and metrics remain unchanged.
