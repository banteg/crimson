# `quest_build_the_lizquidation`

Native target: `crimsonland.exe` at `0x00437c70` (245 bytes).

Live Binary Ninja evidence recovers ten paired template `0x2e` lizard waves
from the right and left edge midpoints. Each wave uses count `wave + 6` and
trigger `wave * 8000 + 1500`. Wave four also emits one template `0x2b` alien
at `(terrain_width + 128, terrain_width / 2)`, trigger 1500, count 2. The
result contains 21 entries.

The candidate preserves the native base-plus-count record builder, integer to
float coordinate conversions, 24-byte record stride, loop arithmetic, branch,
and output count. VC6 6.5 `/O2 /G6` compiles to the same 79 instructions with
all three references resolved and scores 49.37%, improving the default `/GB`
profile by 37.22 fuzzy-weighted bytes (34.18% to 49.37%). The remaining score
is a VC6 allocation and scheduling split: the candidate cycles the loop,
trigger, and entry-pointer registers and fills x87 latency slots with
independent metadata stores in a different order.

Cursor-based storage, an inlined `next()` method, whole-vector and all-fields
setters, and declaration/lifetime variants were checked. A complete
6.5/6.5pp/7.0 optimizer matrix found `/G6` on VC6 6.5 to be the strongest
profile, though it does not reproduce the native shape exactly. Recovery is
semantic-complete; the residual is compiler register allocation and scheduling
rather than missing behavior. Dummy dependencies and volatile state are not
used to steer the compiler.

## 2026-07-27 focused family pass

Fresh live Binary Ninja decompilation reconfirmed all ten paired lizard waves,
the wave-four alien, and the final count of 21. The compiler matrix after the
retained change leaves MSVC 6.0, 6.5, and 6.6 tied; 6.5 Processor Pack and
7.0 regress to 48.40764331210191%. `/G6` remains uniquely strongest:
`/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` score only 35.443037974683544% and
lose one matched reference.

`loop-lifetime-and-metadata-mutations.json` (SHA-256
`fedc67f3936d019124ffda1d22e5cf728022c08e29fa42976bb62ad8e9b5c3c1`)
recorded all 20 single and pair variants. Declaring the semantic wave
induction value before the zero-count builder is the sole win; every
interaction with direct metadata or reversed wave-local order is byte-neutral
relative to it, so only that declaration-order change is retained.

The validated result improves 120.9493670886076/245 to
124.05063291139241/245 weighted bytes, reducing the gap from
124.0506329113924 to 120.94936708860759 and raising the match from
49.36708860759494% to 50.63291139240506%. It remains 79/79 instructions,
prefix four, and references 3/0/0.

## 2026-07-29 indexed-record and register-lifetime pass

The indexed-record shape that improved the related Syntax Terror and Gauntlet
builders was still untested here. `indexed-record-expression-mutations.json`
(SHA-256
`f3f71190bec1c4b6d4036bdb4579c94e756353484d6656a4aa8da12ad46e3cc0`)
evaluated all 26 single, pair, and triple combinations across the right, left,
and optional wave-four records. Replacing only the optional alien's retained
record pointer with separate indexed expressions is the sole win. It adds
3.1012658227847965 weighted bytes without changing the instruction or
reference counts; both ordinary waves are byte-neutral and every pre-advance
form regresses.

That change exposed one useful declaration boundary.
`register-lifetime-refinement-mutations.json` (SHA-256
`6a45c923c569a18d6a278abb4c4dc70cf3a96c2de3151a7acfb623916cfcc8c6`)
evaluated all 14 declaration-order and builder/wave interactions. Moving the
record pointer declaration between `spawn_count` and `trigger_time_ms` adds
another 9.303797468354432 weighted bytes and assigns the record pointer to the
native ESI role. The equivalent pointer-first order compiles identically, so
the smaller declaration move is retained.

`remaining-local-order-mutations.json` (SHA-256
`bd46308fe876ce025ff48449e8200b704825378359ea70431001df2be75675dc`)
records the sixth and final local-order permutation; it is byte-neutral. The
remaining systematic delta is the compiler's exchange of the wave and trigger
registers. The validated source SHA-256 is
`262f2e2af6b03d552e051f82b5cb1cf08854470348440764df9d33e2cf230f34`.
It now scores 136.45569620253164/245 weighted bytes, or
55.69620253164557%, with a 108.54430379746836-byte gap, 79/79 instructions,
prefix four, and references 3/0/0.

## 2026-08-08 house-style recovery

The recovered builder family style resolves most of the former whole-loop
allocation residual. Repeating the two derived expressions at their semantic
publication sites, rather than retaining named wave locals, assigns the native
roles naturally: EDI is the wave index, EBX is the trigger time, EBP is the
spawn count, ECX is the append count, and ESI is the current record. That step
alone raises the match to 74.68% without changing the 79-instruction shape.

The opening entry is the allocation boundary for the entire loop. Publishing
its metadata before its independent position fields makes VC6 establish the
shared trigger/count values before the two position walks; later entries keep
the usual complete-entry-then-append form. Declaring the zero-count builder
before the wave induction variable then reproduces the native initialization
order. Together these source-level boundaries raise the candidate from 55.70%
to 88.61%, extend the exact prefix from four to seven instructions, retain
79/79 instructions, and resolve references 5/0/0.

Scalar and vector full-entry helpers, a shared metadata aggregate, an indexed
post-advance publication, and alternate helper store orders were rejected.
They either introduced stack temporaries, changed the record cursor, or lost
the native register roles. The remaining delta is confined to independent
opening metadata/position scheduling and the second entry's x87 latency slots.
Source SHA-256:
`b15cc30638c7f58de6058962ce2af57458c63b956c5e95069f389534abd5a98a`.

## 2026-08-09 indexed second-entry publication

The recovered house style has one further useful mixed publication boundary.
The second wave entry keeps its retained record pointer for the two position
fields, but publishes metadata through `builder.spawns[builder.count]`. This
ordinary indexed helper receiver lets VC6 keep the native metadata order after
the y conversion. The first entry's equivalent indexed receiver is byte-neutral,
as are direct metadata fields, `while`/guarded loop spellings, and the inverted
optional-entry guard.

Pre-advancing the append count, retaining named trigger/count values, scalar or
vector full-entry helpers, and a shared metadata value all regress. A two-field
vector setter moves the x store and count increment away from their native
slots. Split opening metadata publication also loses the register/lifetime win
from the existing helper-before-position boundary.

The retained one-line change raises the match from 88.60759493670886% to
89.87341772151899%, adds 3.1012658227847965 fuzzy-weighted bytes, and preserves
79/79 instructions, prefix seven, and references 5/0/0. The remaining delta is
the opening entry's independent derivation/publication schedule plus one
second-entry `cmp`/`fild` swap. Source SHA-256:
`32d4b058847212f25f56234c5cfe46d98f52d3f4f93d2ea753cb2553cab981ce`.

## Opening value-lifetime replay (2026-08-11)

Native derives the first wave's trigger and count before its position
conversions. `opening-value-lifetime-mutations.json` replays all six ordinary
declaration orders for trigger, count, and current entry against the retained
helper-before-position source. All six variants are byte-identical at 89.87%,
79/79 instructions, prefix seven, and `5/0/0` references. Named values do not
recover the remaining publication schedule, so no source change is retained.
The spec SHA-256 is
`c8c9960532fc0b055c092b5e2200a468187d2656905743d377a88fab0076d7fc`.

## Live residual and owner replay (2026-08-12)

The compiler-residual classification was rechecked rather than accepted from
the older notes. Fresh native disassembly and the normalized current diff
isolate three concrete differences: native derives the first trigger and count
before the record pointer, advances the append count before publishing that
record's metadata, and schedules the wave-four comparison between the second
entry's `fild` and `fstp`.

Eight current-source sweeps cover 37 compile-valid variants for those exact
hypotheses:

- `opening-entry-publication-mutations.json` and
  `opening-advance-before-metadata-mutations.json` replay metadata after the
  position stores, including the previously missing append-count advance
  before metadata. Every form regresses to 77.22% or 78.48% and loses one
  resolved reference.
- `opening-value-lifetime-mutations.json` reconfirms all six trigger, count,
  and entry declaration orders as byte-identical.
- `optional-wave-condition-mutations.json`,
  `second-entry-condition-placement-mutations.json`, and
  `second-entry-y-lifetime-mutations.json` cover direct, named, split, integer,
  and x87-carried midpoint/condition lifetimes. All ordinary forms are
  byte-identical; only subtraction-based comparison regresses.
- `builder-next-opening-interactions.json` tests an inlined postincrementing
  `builder.next()` owner. The unused helper is neutral, while every valid call
  interaction regresses to 87.34% or 77.22%.
- `plain-entry-owner-mutations.json` replaces the builder with the direct entry
  table and integer append count suggested by the decompiler view. Both
  declaration orders fall to 29.14% and `3/0/0` references, decisively
  rejecting that whole-function owner shape.

The source therefore remains at `220.18987341772151/245` weighted bytes
(`89.87341772151899%`), 79/79 instructions, prefix seven, and `5/0/0`
references. The current evidence supports the retained builder and publication
shape; reproducing the remaining independent schedules would require an
artificial dependency or register constraint.

## Profile override revalidation (2026-08-15)

The retained source has changed enough that the historical `/G6` override is
no longer the strongest profile. A fresh same-compiler comparison under
MSVC 6.5 gives the canonical `/O2 /GB /W3 /GR-` profile
`223.2911392405063/245` weighted bytes (91.14%), versus
`220.18987341772151/245` (89.87%) under `/G6`. Both emit 79/79 instructions,
prefix seven, and `5/0/0` references. Removing the stale override therefore
recovers 3.1012658227848 weighted bytes without an instruction, prefix, or
reference tradeoff and restores the executable's provenance-backed default
profile.
