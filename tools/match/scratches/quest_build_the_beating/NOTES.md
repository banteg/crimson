# `quest_build_the_beating`

## Current result: exact (2026-09-04)

The first three repeated phases now use a zero-based wave index to derive
positions. The first phase also derives trigger time from that index. Canonical
MSVC 6.5 `/O2 /GB /W3 /GR-` produces 100%, 649/649 weighted bytes,
166/166 instructions, prefix 166, and `8/0/0` references, up from 95.78%.
This removes the one-step-ahead X workaround and recovers both later phase-entry
cursor/conversion schedules. Spawn positions, times, and phase lengths remain
unchanged: eight right waves, eight left waves, and six ghost waves.

`wave-induction-recovery-mutations.json` records nine controls. Ordinary X
postincrement alone regresses; deriving the first phase's position and time
reaches 98.80%. Recovering either later phase reaches 99.40%, and combining
them reaches 100%. Deriving the later trigger times too is byte-neutral. The
historical compiler-residual conclusion below did not account for this source
induction structure and is superseded by the exact result.

## Historical investigations

Native target: `crimsonland.exe` at `0x00435610` (649 bytes).

Live Binary Ninja evidence recovers 31 entries in seven phases:

- one template `0x27` bonus at (256, 256), trigger 500 ms, count 1;
- one template `0x29` AlienBigGray at `(width + 32, height / 2)`, trigger 8000 ms,
  count 3;
- eight template `0x25` waves at `(width + x, height / 2)`, where `x` starts
  at 64 and advances by 32, triggers start at 10000 ms and advance by 100 ms,
  and every count is 8;
- one template `0x29` AlienBigGray at `(-32, height / 2)`, trigger 18000 ms, count 3;
- eight template `0x25` waves at `(x, height / 2)`, where `x` runs from -64
  through -288 by -32, triggers start at 20000 ms and advance by 100 ms, and
  every count is 8;
- six template `0x0f` waves at `(width / 2, y)`, where `y` runs from -64
  through -274 by -42, triggers start at 40000 ms and advance by 100 ms, and
  every count is 4;
- six template `0x12` rings at `(width / 2, width + 44 + y_offset)`, where
  `y_offset` starts at 0 and advances by 32, triggers run from 40000 through
  40500 ms, and every count is 2.

The final phase deliberately derives both coordinates from terrain width. This
native detail also corrected the Zig quest port, whose prior y coordinate used
height and only happened to agree on square maps. Heading remains untouched.

The retained append-count candidate represents all 166 native instructions,
resolves all eight audited global references, and scores 95.18% with a
39-instruction exact prefix. One continuous count publishes all 31 entries and
supplies the returned count, replacing four phase-specific cursor starts and
the fixed final assignment. The remaining 31.2771 weighted bytes are VC6
instruction scheduling and equivalent address encoding within otherwise
aligned position-conversion loops.

An earlier intermediate candidate advanced the opening walk's X offset
immediately after constructing the current position and before storing spawn
metadata. Live Binary Ninja shows the update between the coordinate
calculation and the template/trigger/count stores. At that stage, this source
order preserved offsets 64 through 288 and triggers 10000 through 10700 while
improving the exact prefix from 22 to 37 instructions and the match from 53.61%
to 54.82%.

That intermediate candidate also advanced each repeated walk's entry cursor
before writing the current entry's metadata, then addressed the completed entry
as `spawn[-1]`. This is the native dataflow: the first walk advances ECX at
`0x004356b3` before coordinate stores at `0x004356de..0x004356e9` and metadata
stores at `0x004356ec..0x004356f6`; the later walks repeat that shape at
`0x0043577a`, `0x004357dd`, and `0x00435838`. Using direct fields after the
cursor advance improves the match from 54.82% to 68.07%, raises weighted
matched bytes from 356 to 442, and reduces the weighted gap from 293.2229 to
207.2108 bytes while preserving the 37-instruction prefix, exact 166/166
instruction count, and `7/0/0` references.

The combined cursor/dataflow recovery is material: applying it only to the
first walk reached 56.02% but temporarily aligned only six references.
Retaining the helper call after advancing the cursor regressed to 26.19% with
170 instructions, a one-instruction prefix, and `2/0/1` references. Introducing
a separate current-entry pointer or reference also emitted 170 instructions
and regressed to 43.45%, so those variants were rejected.

Recovery is classified `semantic-complete` with a `compiler` residual.

## Profile and fixed-position audit

MSVC 6.0, 6.5, 6.5 Processor Pack, and 6.6 tied at the
68.07228915662651% baseline; MSVC 7.0 regressed to 44.64% with references
5/1/0. `/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tied, while `/G6` regressed.

`fixed-position-store-mutations.json` (SHA-256
`fbea9d4516b925edd0ff05344e55e6f42503a675c57c78322adc714460542854`)
recorded seven variants. Its `left-big-alien-position/direct-fields` variant
appears to improve the fuzzy score from 68.07% to 73.78%, but does so by
deleting the four stack-temporary instructions present in native and moving
the candidate from 166/166 to 162/166 instructions. The matcher now classifies
that result as `instruction-count-further-from-target` and refuses to select it
as an automatic winner. The whole-vector assignment is restored as the
evidence-backed canonical source at 68.07%, 166/166 instructions, prefix 37,
and `7/0/0` references.

## First-line cursor/offset ordering audit

Live native disassembly advances both the entry cursor and x offset inside the
first coordinate-conversion window. `first-line-advance-order-mutations.json`
(SHA-256 `df2bdeabb596459e7475753725fff7e720e9d199df7c6aac99f89d207fbf09c8`)
tested the remaining cursor-before-offset source order. VC6 emitted identical
bytes, so the canonical ordering and 68.07% score remain unchanged.

## Trigger-field cursor audit

The native register at each repeated walk is biased to the current entry's
`trigger_time_ms` field and advances by the six-word entry stride before the
completed entry is addressed through negative offsets. This is the same
interior-cursor shape recovered in neighboring quest builders, so
`trigger-field-cursor-mutations.json` (SHA-256
`0bc5ee9315638da0568078ce8a1ab7cb13dd6f80ec79f9702430b1ee172ca383`)
tested it independently in the right, left, ghost, and ring walks.

All fifteen single, pair, triple, and complete four-walk combinations were
rerun against the restored whole-vector source and compile to exactly the
same 166-instruction candidate: 441.7892 weighted bytes, 68.07%, a
37-instruction prefix, and `7/0/0` references.
The explicit `int *` trigger cursors and negative metadata offsets are therefore
source-equivalent under VC6 optimization; they do not recover the native
register assignment. Together with the earlier current-entry pointer,
reference, helper-call, and advance-order sweeps, this closes the natural
cursor-type and cursor-lifetime search without encoding an artificial
dependency.

## First-walk value-lifetime follow-up

`right-wave-position-lifetime-mutations.json` tests five named integer/float X
and center-Y lifetimes around the first repeated walk. All five preserve the
166-instruction count and clean references but lose 3.93 weighted bytes; none
reproduces native's delayed height load. The complete sweep has SHA-256
`cad213e7776f42bcf057868fefeb5ba333aeca9a1bdc0df29afaaf1ff9ec99c0`.

`right-wave-advanced-trigger-cursor-mutations.json` then expresses the native
advance-first interior pointer directly and publishes the position through a
vector pointer, a named vector pointer, or a recovered entry pointer. The two
named forms are byte-neutral and the direct cast loses 7.80 weighted bytes.
The initial authoring record failed because it also removed the later-used
`spawn` declaration; the corrected complete three-variant run has SHA-256
`18b8e2ab967f8e022e9bce831e17e83d21184d17e5b22ebc0932031220e8752b`.
No variant changes the compiler's chosen entry-base induction register.

## 2026-08-08 append-count recovery

Replacing the four hardcoded repeated-walk cursors and fixed output count with
one continuous append count improves the retained candidate from
441.789156626506/649 weighted bytes (68.07%) to
504.3433734939759/649 (77.71%). It also extends the exact prefix from 37 to 39
instructions while preserving 166/166 instructions and references 7/0/0.
The source remains a direct expression of the recovered 31-entry script; the
remaining differences are localized load, x87-store, and cursor-advance
scheduling. The retained source SHA-256 is
`22d545378aee4fd749fed2b132033db2f34f1659411f46c677ffba56a6b2797e`.

## 2026-08-10 first-wave publication scheduling

A bounded operation-order sweep exposed the first walk's one-step-ahead X
cursor. Advancing `x_offset` before publishing the position and reading the
current offset as `x_offset - 32` preserves the recovered coordinates 64
through 288. Declaring the later left-walk trigger before its X cursor preserves
the same 20000 through 20700 ms schedule while matching VC6's register lifetime.

Together, these source-equivalent orders improve the retained candidate from
504.3433734939759/649 weighted bytes (77.71%) to
617.722891566265/649 (95.18%). The exact prefix remains 39 instructions, the
instruction count remains 166/166, and audited references improve from `7/0/0`
to `8/0/0`. `first-wave-offset-publication-mutations.json` records the retained
cutover with SHA-256
`e92db069a27bda2066069c8065c704b0fdf97f2e125048c7562da5b8f8f4373d`.
The retained source SHA-256 is
`74a67a7a2bd56a400f02fdf590329356f86c4d47d5731602646c385e1aa755ca`.

## First-wave entry-publication bound (2026-08-11)

Live native code advances the first repeated-wave entry cursor before forming
the current X coordinate. `first-wave-entry-publication-mutations.json` tests
the corresponding preincremented index, postincremented pointer/reference,
and advance-then-pointer ownership forms while preserving all eight positions,
triggers, and counts.

All four variants regress: the closest preincremented-index form falls to
76.51% and prefix 37, while the three pointer/reference forms fall to 66.87%
and prefix 22. None improves the 95.18%, 166/166-instruction baseline, so the
retained one-step-ahead X expression remains the strongest natural source.
The spec SHA-256 is
`9dc6153f9543253af7e505bd7caa005a96a2282eda04f5a06f03d9eea7d59e28`.

## Current phase-schedule replay (2026-08-12)

The older cursor and lifetime conclusions predated the retained continuous
append count and one-step-ahead first-wave X expression, so they were not
treated as current evidence. A fresh normalized diff isolates the 31.2771-byte
gap to the first-wave cursor/X advance order, two later phase-entry `lea` / x87
input-store swaps, one equivalent ring-Y `lea` operand encoding, and the branch
displacements induced by those byte choices.

Five current-source sweeps evaluate 70 bounded variants:

- `coordinate-expression-order-interactions.json` exhausts all 29 single and
  paired commutative forms for the first-wave X and ring Y. Every object is
  byte-identical to the baseline, so expression-tree spelling does not select
  either LEA encoding.
- `phase-position-owner-interactions.json` crosses references, pointers,
  entry owners, and named vector values in the left and ghost phases. All 24
  variants are byte-identical; naming the destination cannot move the phase
  entry address ahead of the independent scalar store.
- `phase-entry-cursor-interactions.json` tests loop-spanning entry cursors in
  both position-then-advance and advance-then-previous forms. Singles regress
  by 27 to 31 weighted bytes, and pairs regress by 55 to 70.
- `current-right-x-lifetime-mutations.json` retests the native-looking
  pre-advance X snapshot against the current allocator. All five forms lose
  109 to 113 weighted bytes and one resolved reference, confirming that the
  retained one-step-ahead expression is a whole-function allocation boundary.
- `ring-y-lifetime-mutations.json` tests complete, split, reordered, and
  shared-base ring-Y locals. The first three are byte-identical; sharing the
  base loses 50 weighted bytes and one reference.

The source remains `617.722891566265/649` weighted bytes
(`95.18072289156626%`), 166/166 instructions, prefix 39, and `8/0/0`
references. The current evidence closes the natural expression, destination,
cursor, and coordinate-lifetime routes without using register hints or
artificial dependencies; `RESIDUAL=compiler` remains appropriate.
