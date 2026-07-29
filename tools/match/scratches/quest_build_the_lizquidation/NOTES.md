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
