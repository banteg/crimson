# `highscore_screen_update`

Native target: `crimsonland.exe` at `0x004423d0` (8,026 bytes).

Live Binary Ninja disassembly and decompilation recover the complete high-score
screen callback:

- derives both UI panels from element slots 09 and 33, draws the current-mode
  title, quest selector, score headings, Hardcore toggle, and ten formatted
  score rows;
- distinguishes time-based Rush/Quest records from score-based modes, preserves
  the native internet-record marker, and renders the hovered record detail with
  its one-based rank;
- implements the date, player-count, game-mode, internet-score, and profile
  controls, including the native one/two-player choices and Typ'o'Shooter clamp;
- handles Update/Receive, Shift batch synchronization, every connection status,
  post-sync update checks, and the update-notice widget;
- routes Play, Back, Escape, keyboard quest navigation, and mouse arrow actions,
  including return-to-results pool cleanup and restoration of the saved mode;
  and
- proves all nine local-static destructor thunks at `0x00444330` through
  `0x004443b0` as exact one-instruction returns.

The natural `msvc6.5 /O2 /GB` reconstruction matches 77.21% of 2,004 target
instructions with 1,962 candidate instructions. The candidate has the native
`0x84`-byte frame, a 41-instruction matching prefix, and audited references of
`581/0/8` (ok/unresolved/mismatch). The eight residual reference mismatches are
instruction-alignment or x87 temporary-order differences; every corresponding
field, constant, string, and gameplay object is present in the recovered flow.

The Quest filter performs its unlock-bound check independently in the normal
and Hardcore arms. Native computes the selected quest index in each arm, loads
the corresponding unlock counter, and tail-merges only the identical clamp and
table-reload body. Recovering that shape adds six candidate instructions and
four aligned references. The adjacent Hardcore checkbox gate keeps its enabled
arm as the fallthrough (`quest_unlock_index >= 40`), matching the native branch
layout. Together these changes raise the score from 76.92% to 77.21% and add
23 fuzzy-weighted bytes without changing behavior or the exact frame.

The Shift batch synchronizer at `0x00443b23..0x00443c2a` is a chained
stage machine rather than a switch lowered around shared case tails. Stages
`-3`, `-2`, and `-1` select Survival, Rush, and Typ'o'Shooter through explicit
`if`/`else if` arms. Negative stages then branch directly to the shared sync
start, while nonnegative stages reject normal and Hardcore quest indices
through separate invalid-first comparisons before validating the major stage.
Expressing that native control flow removes an unsupported `start_sync` local,
keeps the exact frame and instruction prefix, aligns ten additional
references, and raises the whole-function score from `75.85%` to `76.92%`.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, unreachable shaping, or platform substitutions are used.

The score-line builder now carries a typed
`char (*)[164]` cursor through the ten-row backing array. This expresses the
native `+0xa4` row stride directly instead of byte arithmetic, keeps the
evidenced `char *` item table separate from its storage, and is matcher-neutral
at **77.21%**, the exact `0x84`-byte frame, and reference audit `581/0/8`.

The left panel origin is one chained vector expression:
`element position + first vertex + (300, 40)`. Native keeps the first sum and
the final sum in separate temporary slots before copying the result into the
live screen cursor, exactly as the same source idiom does in the recovered
options and Alien Zoo Keeper screens. Replacing the named intermediate
`operator+=` with that value expression keeps all 1,962 candidate instructions,
the exact frame, and `581/0/8` references while improving the prefix from 41 to
45 instructions, the score from **77.21%** to **77.31%**, and fuzzy coverage by
8 bytes. Applying the analogous rewrite to the later right panel was measured
separately and rejected because it disrupts the aligned lifetime map.

Native then advances the live cursor component by component: `x` starts from
the chained panel result before adding the UI render offset and constants, while
`y` adds one independently. Expressing those two scalar assignments instead of
constructing another temporary vector keeps all 1,962 instructions and the
45-instruction prefix, improves the score to **77.36%**, adds another 4 fuzzy
bytes, and improves the reference audit from `581/0/8` to `583/0/7`.
Reading the already-copied panel components directly was also isolated, but
lost 8 fuzzy bytes and one aligned reference; keeping the live `position`
assignments preserves the native lifetime implied by the copy.

The native score-row loop carries three distinct induction pointers: a
`char **` cursor through the ten item slots, a `uint8_t *` cursor anchored at
`highscore_record_t::flags`, and a `char (*)[164]` cursor through the row
buffers. Binary Ninja now retains those names and types, along with the
row count, escape-prefix length, and three branch-local player-name pointers.
The record cursor deliberately remains an interior byte pointer: previewing it
as `highscore_record_t *` mislabeled `flags` as `player_name[0]`, because the
native register contains `&record->flags`, not the owning record base. The
remaining negative offsets are therefore honest evidence of VC6's interior
induction variable rather than missing owner-type recovery.

The stack slots holding score number and selected row are coalesced with
unrelated render coordinates and later item pointers. Split-local type
previews polluted those other lifetimes, so they are intentionally left
unannotated until Binary Ninja can represent the compiler's stack-slot
lifetime splits without widening the user type across the whole function.

The matching source now carries the score-record walk as the native
`unsigned char *` cursor anchored at `highscore_record_t::flags`, advances it
by the proven `0x48` record size, and recovers the owning record with
`offsetof` only where the name, elapsed time, or score is needed. It also
clears each row through the item pointer just assigned to that row, preserving
the target's item-before-clear data flow without raw offsets. This raises the
whole-function result from **77.36%** to **77.42%**, adds 4.70 fuzzy-weighted
bytes, and reduces the candidate from 1,962 to 1,959 instructions while
retaining the 45-instruction prefix and `583/0/7` reference audit.

Live disassembly at `0x004424c0..0x004424f2` further constrains the opening
panel arithmetic. Native adds the render offset, `44`, and subtracts `110`
from `position.x`, keeps that result on x87 while advancing `position.y` by
one, and only then subtracts the final `32` from `x`. Splitting that final
subtraction around the real `y` update preserves the arithmetic and all 1,959
candidate instructions while reproducing the native operation ordering. The score rises
from 77.4161% to 77.5170%, fuzzy gap falls from 1,812.5839 to 1,804.4830 bytes,
and the audit improves from `583/0/7` to `584/0/7`; the `0x84` frame and
45-instruction prefix remain exact.

A fresh profile matrix found no better compiler override. VC6.5 and VC6.6
produce the same best body under `/O2 /GB`; `/G5`, `/TP`, and `/GX` are
byte-neutral. VC6.0 falls to 75.4156%, `/G6` to 66.5994% under VC6.5, and the
Processor Pack to 64.5979%; the tested `/O1` and `/Oy-` variants do not improve
the baseline.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja output covers the score rows, all filters,
local-static widgets, online worker and batch state machine, notices, and
every Play/Back/high-score-return route. IDA and Ghidra corroborate the same
16-callee surface. The 1,959/2,004-instruction candidate keeps the native
`0x84` frame, a 45-instruction prefix, and `584/0/7` references; the first
bounded regions differ only in x87 ordering, coalesced stack slots, and
instruction scheduling. The seven audited mismatches likewise pair adjacent
but differently scheduled operations: the record-table flags cursor and
score-line buffer, three consecutive music IDs, the saved minor/mode/major
return tuple, a render-coordinate constant, and adjacent player-count widget
fields. Binary Ninja confirms the native addresses and the matcher separately
resolves every corresponding candidate object. They remain visible and
unaliased at `584/0/7`, but carry no independent source-reference debt.

## Recorded opening-lifetime mutation sweeps

Fresh evidence came from live Binary Ninja target
`3023:2:9499448411019345244`. The complete native disassembly has SHA-256
`eb1f5ecc6d7cba3df812b4f39397d3683c2141fbec0e366e2ba6088acd86be61`;
the corresponding decompilation has SHA-256
`be8d6f524ac3d3906b4685f340d955843f7ad52f2c5ce8f54523baa9fc4019fd`.
The fresh baseline source SHA-256 is
`0bcc139286d6cb9ed4b4ee5a870324e08e1f6f994278d329507b92b844dad7c7`
and reproduces **77.5170%**, gap `1804.4830`, 1,959/2,004 instructions,
prefix 45, and references `584/0/7`.

`opening-lifetime-mutations.json` is a schema-1, three-site specification
covering only panel copy initialization, title-local declaration timing, and
separator coordinate materialization. Its SHA-256 is
`6ac4132dcc22d60944a3ac1aace3c79ca40f1dbb4e6989f1b67018389cbb1336`.
A recorded `--max-changes 1 --max-variants 11` sweep evaluated all 11/11
singles:

| rank | source shape | match | gap | candidate/native | prefix | refs |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | panel `position-then-left-copy` | 77.5335% | 1803.1625 | 1953/2004 | 45 | `583/0/7` |
| 2-7 | four title declarations, named separator coordinates, position declared first | 77.5170% | 1804.4830 | 1959/2004 | 45 | `584/0/7` |
| 8 | separator component assignment, x first | 77.4161% | 1812.5839 | 1959/2004 | 45 | `583/0/7` |
| 9 | separator component assignment, y first | 77.3152% | 1820.6848 | 1959/2004 | 45 | `582/0/7` |
| 10-11 | panel assignment after declaration | 75.9021% | 1934.0979 | 1959/2004 | 43 | `569/0/15` |

Because one single was numerically positive, a second recorded sweep used
`--max-changes 2 --max-variants 51`. It completed 11/11 single and 40/40 pair
coverage with no unevaluated combinations. The top pair combined
`position-then-left-copy` with y-first separator component assignment:
source SHA-256
`257eb414f50dbce2feed8666577be22de99c368c665ea6859269f044cc536831`,
**77.5840%**, gap `1799.1059`, 1,953/2,004 instructions, prefix 45, and
`584/0/7` references. The x-first pair ranked second with identical score and
gap, source SHA-256
`f16f914d0b61905857e388070e2192c7d1ad7fde867170da95fc5846395c30d5`,
but only `583/0/7` references. The single remained third. Both complete
records are in `experiments.jsonl`, whose SHA-256 after the sweeps is
`0b2d9db15c412e58e601dda5b1a30d1dc3342a7b98220c055dd39ab1de4e0e91`.

The apparent winners are rejected by localized native evidence. At
`0x0044249b..0x004424de`, native materializes the final panel X and Y in
`[esp+0x64]` and `[esp+0x68]`, then copies them through EDX and EAX into the
live `[esp+0x20]` and `[esp+0x24]` cursor. Swapping the source declarations
makes the initial `left_panel` copy dead before its later overwrite and removes
all six materialize/copy instructions; the provisional candidate jumps from
the first sum directly to `[esp+0x24]`. Its whole-function score increase is
therefore an alignment artifact opposite the native data flow.

Native separator construction at `0x00442587..0x004425c6` likewise computes
and stores X first, then loads `position.y`, adds 14, and stores Y before the
outline call. The top interaction explicitly assigns Y first, while its
x-first sibling still depends on the rejected panel-copy deletion. No
numerical winner is locally evidence-backed, so neither source mutation is
retained. The title declaration spellings and named coordinates compile
byte-identically; the other natural spellings are decisive regressions.
The scratch therefore keeps its original source hash and remains
`semantic-complete` with a `compiler` residual, without volatility, fake
arithmetic, dummy addressing, assembly, or register forcing.

## Recorded pool-reset loop sweep

The remaining five pool-reset loops are another plausible source of local
cursor and induction-variable differences. The schema-1
`pool-reset-loop-mutations.json` spec covers the bonus, projectile, sprite,
secondary, and creature clears with three native-compatible spellings at each
site: the retained signed pointer walk, an indexed `do/while`, and an indexed
`for` loop. Its SHA-256 is
`bb4f8a357bd529e990879ca66ae2df2af7c9f51a7068a785091530badc1fdd68`.

A recorded single-site sweep evaluated all 15/15 variants. Every alternative
compiled byte-identically to the canonical source: **77.5170%**, gap
`1804.4830`, 1,959/2,004 instructions, prefix 45, and references `584/0/7`.
This complete null result shows that VC6 canonicalizes these natural source
spellings and rules out the five loop forms as an explanation for the
residual without introducing artificial codegen controls. The source remains
unchanged. The updated `experiments.jsonl` SHA-256 is
`0c6437f16e799574f9d4e0f4edfb704e60759ea5b29f2394884b77675ac9641e`.

## Native data-flow and branch-shape residual pass

A fresh pass against explicit Binary Ninja target `crimsonland.exe.bndb`
revisited the three largest residual families instead of assuming that every
remaining mismatch was compiler noise. The incoming source SHA-256
`0bcc139286d6cb9ed4b4ee5a870324e08e1f6f994278d329507b92b844dad7c7`
reproduced **77.5170%**, `6221.517032551098/8026` fuzzy-weighted bytes,
gap `1804.482967448902`, 1,959/2,004 instructions, prefix 45, and references
`584/0/7`.

### Score-row assigned-item data flow

Native `0x00442b92..0x00442c41` first stores the current backing buffer through
the `char **` item cursor, then obtains the escape-prefix and `crt_sprintf`
destinations by loading that assigned item. The port instead bypassed the
item table and wrote through the backing-buffer cursor directly. Both address
the same bytes, but the latter was less precise source data flow and forced
the item cursor out of the native EBP allocation.

`score-row-destination-mutations.json` (SHA-256
`9ac94413e2eaee896fcc22889914f0532ff768f5a53e738f9ea2d624977e13d5`)
tested prefix-only, format-only, and combined rewrites. The singles regress by
`0.658737` and `56.999279` weighted bytes respectively, while their
native-evidenced interaction gains `19.804548914528` weighted bytes and three
aligned references. The retained combined source reaches **77.7638%**,
`6241.321581465626` weighted bytes, gap `1784.678418534374`,
1,967/2,004 instructions, prefix 45, and `587/0/7` references.

The adjacent `switch` was also challenged because native keeps distinct Rush
and Quest formatting arms. All three natural `if`/`else if` spellings in
`score-row-mode-mutations.json` (SHA-256
`07691805fd5352491c6fececc0cc639c72a63c1a4e356658621e2b19c597f856`)
compile to the same 1,966-instruction candidate and lose
`51.403178646816` weighted bytes plus one aligned reference. The switch is
therefore retained: its tail merge is a compiler/code-layout effect, while
the assigned-item loads are directly visible native data flow.

### Batch synchronizer fallthrough

At `0x00443ae7..0x00443b23`, native branches to the Quest arm and leaves the
non-Quest zeroing path as fallthrough. Inverting the equivalent source
condition to `game_mode != GAME_MODE_QUEST` reproduces that layout without
changing behavior. The one-variant
`batch-hardcore-branch-mutations.json` sweep (SHA-256
`37f5c8c555d53543b63cecefbbba29a5ec55e42d594cc6486c99c7da32efd5b3`)
gains `4.042306723747` weighted bytes and one aligned reference, reaching
**77.8142%**, `6245.363888189373` weighted bytes, gap
`1780.636111810627`, and `588/0/7` references with instruction count and
prefix unchanged.

### Quest-navigation edge fallthrough

Native repeats the same edge-control shape in keyboard-left, keyboard-right,
mouse-left, and mouse-right handlers: the stage movement path falls through
and the comparison branches to the edge clamp. The port expressed all four
equivalent conditions in the opposite orientation. The complete
`quest-navigation-branch-mutations.json` matrix (SHA-256
`34b7d962308d3dc42876509e6fd1aba370b0ffe2775aa8c5eb5f15d55d877d52`)
evaluated all 4 singles, 6 pairs, 4 triples, and the one four-site
combination. Each site independently adds `4.042306723748` weighted bytes;
the retained four-site winner adds `16.169226894988` with no reference,
instruction-count, or prefix tradeoff.

The final source SHA-256 is
`cb069154c9da406e88b327e9c6982e5268ae8cc8961b913c6d0a1c7df8855595`.
It matches **78.0156%**, `6261.533115084361/8026` weighted bytes, gap
`1764.466884915639`, 1,967/2,004 instructions, prefix 45, and references
`588/0/7`. Relative to the incoming baseline this is
`+40.016082533263` weighted bytes (`+0.498580644571` percentage points),
eight candidate instructions, and four aligned references, with no new
reference mismatch.

### Rejected lifetime probes and final profile

The four recorded return-state captures in `return-state-mutations.json`
(SHA-256
`7e49ddb65482032150d9d248c9479718e7f98f177d008ffe8c879172bbfbd1f7`)
found one byte-neutral spelling; the other three lose
`117.226894988668` weighted bytes and change the audit to `575/0/13`.
Fresh localized probes likewise reject explicit right-panel copy/update
lifetimes (**75.5902%**, prefix 43, `570/0/13`), moving the player-count
array ahead of its local static (**77.1090%**, prefix 1, `579/0/8`), and
materializing a shared profile-menu position (**75.2077%**, `568/0/12`).
Those shapes either perturb the whole-function stack lifetime map or lose
native reference alignment, so none is retained.

A recorded control probe of the accepted row-cursor source before the batch
and navigation changes reproduces **77.7638%** and is
`20.211533618735` weighted bytes behind the final source. A live six-profile
matrix confirms that VC6.5 and VC6.6 produce the same final
`6261.533115084361` weighted bytes under natural `/O2 /GB /W3 /GR-`;
adding `/G5` or `/GX` is byte-neutral. `RECOVERY=semantic-complete` and
`RESIDUAL=compiler` remain accurate.

The final `experiments.jsonl` contains ten recorded experiments and has
SHA-256
`b9bf48f26ac0fab17ea553ed0006c5b46f8ad6adb09b341b77effdd09f94e93d`.

## Quest-entry mode lifetime sweep

A fresh live rebaseline reproduces the retained source at **78.0156%**,
`6261.533115084361/8026` fuzzy-weighted bytes, gap
`1764.466884915639`, 1,967/2,004 instructions, prefix 45, and references
`588/0/7`. The active Binary Ninja database was explicitly verified as
`crimsonland.exe.bndb`, target `3023:2:9499448411019345244`.

The first mismatch region at `0x00442483..0x004424f2` remains the previously
audited opening aggregate-slot allocation: native uses `[esp+0x64/0x68]`,
while VC6 assigns the equivalent candidate temporaries to
`[esp+0x5c/0x60]`. The first new material control-flow allocation appears at
`0x004425d6..0x004425e7`. Native loads `config_blob.game_mode` into `EAX`,
loads `GAME_MODE_QUEST` (`3`) into `EDI`, compares them, and then seeds the
literal `1` in `ESI`; the candidate folds the Quest comparison to an immediate
and uses `EDI` for the repeated literal `1`. Native reuses that `ESI` value at
`0x00442837..0x0044284b` for the `1.1` quest-stage edge check. The bounded
native disassembly artifact has SHA-256
`6e08fef0cf4ab676f6217278a9dbb8bc57d81e58d94ba4fa321ebf2bf355d866`.

The schema-1 `quest-entry-mode-lifetime-mutations.json` spec has SHA-256
`c29f4df3600fc9579c5be0cf465cd366f8b6c90c4219ded03fbdb0d9d2760cc8`.
Its recorded sweep exhausts all 6/6 natural one-site spellings: typed and
integer mode snapshots, typed and const Quest constants, a named Quest
predicate, and a commuted comparison. VC6 canonicalizes every variant to the
same baseline bytes, first mismatch, instruction count, prefix, and reference
audit. This rules out ordinary lexical mode lifetime and comparison polarity
as controls for the native `EDI`/`ESI` allocation.

A fresh bounded six-profile matrix independently confirms that VC6.5 and
VC6.6 under `/O2 /GB /W3 /GR-`, with `/G5`, or with `/GX` all emit the same
`6261.533115084361` weighted bytes and `588/0/7` references. No source or
profile change is retained. The canonical source SHA-256 remains
`cb069154c9da406e88b327e9c6982e5268ae8cc8961b913c6d0a1c7df8855595`;
`experiments.jsonl` now contains eleven recorded experiments and has SHA-256
`ea76587be5f7b2cb7dccefb11dd3c03e8bcb422930bcd7788f58640dc9a62aee`.

## Row, pool, panel, and return-state interaction sweeps

Four further bounded sweeps exhaust 139 natural variants while preserving the
retained **78.0156%** baseline as the winner.

`score-row-local-lifetime-mutations.json` (SHA-256
`3af40e0176bad02e0979218d646f11bf400b94085ff86fd7c287c8d6e6ca1395`)
tests six declaration/statement schedules and five escape-prefix lifetimes,
including all 41 singles and cross-site pairs. The neutral leaders reproduce
the baseline exactly; the other schedules regress. This rules out ordinary
row-local declaration order as the cause of the native
`0x00442b4d..0x00442c79` allocation.

Native uses signed `jl` bounds in all five return-to-results pool clears.
`pool-reset-signed-interaction-mutations.json` (SHA-256
`faa1c29b25dd63898c63a5450c93dd4253e5c354d1f772e24a691eb47961b558`)
therefore tests every nonempty combination of explicit signed pointer bounds:
5 singles, 10 pairs, 10 triples, 5 four-site variants, and the all-five
interaction. VC6 canonicalizes all 31 variants to the same candidate bytes.
The branch condition remains a compiler lowering choice, not recoverable
source imprecision.

The native right-panel block at `0x004431b8..0x0044328a` visibly materializes
the aggregate and copies its components before the scalar adjustments.
`right-panel-copy-mutations.json` (SHA-256
`4e6b65df688b1bad38cec414673c266ba1744103827d400a0abdd0e71c4d515d`)
exhausts 63 construction, position-copy, and panel-copy combinations. Only a
component-wise spelling is byte-neutral. Explicit aggregate copies add
instructions but worsen the whole-function alignment and reference audit; the
best non-neutral construction loses `0.889124` weighted bytes. The current
expression remains the strongest compiler-compatible representation.

Finally, `return-state-schedule-mutations.json` (SHA-256
`db8c83ad26f521d82c99ac547e5b58170851c5c2a3d1b9604ec64dbe9ca80287`)
tests four native-load-order schedules for the restored quest stage, mode,
Hardcore flag, and pending state. VC6 emits the same regressing allocation for
all four: `-117.226895` weighted bytes and references `576/0/13`. No source
change is retained.

The canonical source SHA-256 is still
`cb069154c9da406e88b327e9c6982e5268ae8cc8961b913c6d0a1c7df8855595`.
`experiments.jsonl` now contains fifteen complete records and has SHA-256
`47aae4f551dc287b415ae7b977b334efcd6e66faac65c9aff05e0c920df723b4`.

## Scrollbar pointer-range recovery

The two-column constructor was re-audited after the same bounded-loop source
shape improved the perks, weapons, and Mods callers.
`scrollbar-column-loop-mutations.json` evaluates four complete forms. The
two-entry index `for`, `while`, and `do` loops each lose 50.07
fuzzy-weighted bytes and two resolved references. A bounded pointer walk is
the clean winner: it adds two candidate instructions, 4.93 weighted bytes, and
one resolved reference while preserving the 45-instruction prefix and all
seven honest reference mismatches.

The retained result is 78.08%, 1,969/2,004 instructions, and `589/0/7`
references. Current source SHA-256 is
`c4f7a34a755702aff1eae62242f691296de8bd7ceca6a10f72e1cba3d2ecb784`;
the complete append-only experiment ledger SHA-256 is
`f1ed07afc0cb6a1a483ba439931ff646da4cf5e9389b8bef5c6220b67462bc46`.
