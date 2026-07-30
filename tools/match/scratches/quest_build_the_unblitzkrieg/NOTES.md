# `quest_build_the_unblitzkrieg`

Native target: `crimsonland.exe` at `0x00438a40` (975 bytes).

Live Binary Ninja disassembly recovers 81 entries: eight ten-entry perimeter
sweeps with one center entry between the second and third sweeps. Heading is
left untouched and every entry has count one. Each sweep advances an integer
offset from 0 by `0x270` while it is below `0x1860`; dividing that offset by
ten produces the axis coordinate. Templates alternate `0x07`, `0x0d`, starting
with `0x07` in every sweep.

- x=824, y=`200 + offset/10`, triggers 500 through 16700 by 1800;
- y=824, x=`824 - offset/10`, triggers 18500 through 32000 by 1500;
- center (512,512), template `0x07`, trigger 33500;
- x=200, y=`824 - offset/10`, triggers 33500 through 44300 by 1200;
- y=200, x=`200 + offset/10`, triggers 45500 through 52700 by 800;
- x=824, y=`200 + offset/10`, triggers 53500 through 60700 by 800;
- y=824, x=`824 - offset/10`, triggers 61500 through 67800 by 700;
- x=200, y=`824 - offset/10`, triggers 68500 through 74800 by 700;
- y=200, x=`200 + offset/10`, triggers 75500 through 82700 by 800.

The candidate scores 75.95% with a sixteen-instruction exact prefix, exactly
291 candidate and native instructions, and no static-reference debt. It
reproduces the signed division-by-ten lowering, parity-to-template arithmetic,
24-byte stride, loop limits, count reservation, trigger increments, register
frame, and final count. In particular, the first sweep advances the live count
per entry while each later sweep reserves ten entries before looping, matching
the native `add edi, 0xa` boundaries.

Advancing the independent integer offset immediately after the coordinate
expressions is semantics-neutral and recovers the native `add ebp, 0x270`
schedule in most sweeps, improving the fuzzy gap from 291.49 to 241.24 bytes.
The repeated residual is legal independent-store scheduling. Native VC6 uses
the `template_id` field as its cursor base, advances that cursor before storing
template/time/count through negative offsets, and leaves those metadata stores
until after the x87 coordinate conversion. Moving the constant count assignment
out of the metadata helper recovers four exact prefix instructions and 6.70
fuzzy-weighted bytes; the candidate still hoists some trigger stores around
that conversion. Other metadata helper bodies and direct field stores tested
against the earlier three-argument form compile identically. A post-incremented
spawn cursor regresses to 52.97%, and encoding a negative-field cursor would
describe the optimizer rather than plausible game source. No volatile state,
dummy dependencies, or register-forcing constructs are used.

## Semantic-completion audit

Fresh live Binary Ninja HLIL confirms all eight ten-entry sweeps, the inserted
center entry, every axis formula, alternating template expression, trigger
step, and the final count of 81. Address-matched IDA and Ghidra snapshots
independently agree on the signature and absence of callees. Candidate and
target remain exactly 291 instructions with no static-reference debt.

Replacing the direct position stores with a natural vector constructor
regressed from 75.26% to 61.24%, added 32 instructions, and removed the
12-instruction exact prefix. Moving each offset increment after the metadata
stores also regressed to 70.10% while preserving instruction count and prefix.
The retained source is the strongest natural spelling, and the repeated
independent-store schedule is a compiler residual. The scratch is classified
`semantic-complete` with a `compiler` residual.

## 2026-07-27 focused profile and mutation pass

MSVC 6.0, 6.5, 6.5 Processor Pack, and 6.6 tied at
75.25773195876289%; MSVC 7.0 regressed to 36.49%. `/GB`, `/G5`, `/G7`,
`/Ox`, and `/Ob1` were byte-identical, while `/G6` regressed.

`metadata-helper-shape-mutations.json` (SHA-256
`eff4f02fc31cd68015005e127d560fd282e016cfdddf01c662f15aae582e6c6f`)
recorded five complete variants. Explicit-inline, force-inline,
return-by-reference, and count-before-trigger spellings were byte-neutral.
Reversing metadata stores lost 23.4536 weighted bytes and three prefix
instructions, so no variant was retained. The validated source remains at
733.7628865979382/975 weighted bytes, a 241.23711340206182 gap, 291/291
instructions, prefix twelve, and references 0/0/0.

## Two-argument metadata helper provenance

The exact neighboring `quest_build_two_fronts` reconstruction uses a
two-argument `set_spawn(template_id, trigger_time_ms)` helper and assigns the
constant entry count separately. Replaying that same recovered class boundary
here is the first improvement after the 2026-07-27 stopping audit. The recorded
`two-argument-helper-count-after` probe raises the score from 75.26% to
**75.95%**, adds **6.70 fuzzy-weighted bytes**, and extends the exact prefix
from **12 to 16 instructions** while preserving **291/291 instructions** and
`0/0/0` references. The two-argument helper plus direct `count = 1` assignment
is retained because it is both cross-function source evidence and a strictly
better tradeoff-free build.

The new first mismatch is the independent trigger store and offset increment
still moving ahead of the signed coordinate conversion. Count now remains at
the native metadata tail. This narrows the remaining search to trigger/offset
lifetime scheduling rather than the already-recovered entry layout or helper
ABI.

The exact `quest_build_syntax_terror` neighbor also motivated replaying its
`pos.set(x, y)` member boundary across all eight sweeps and the center entry.
The recorded `position-setter-all-sweeps` probe preserves 291/291 instructions
and the 16-instruction prefix but loses 60.31 fuzzy-weighted bytes, falling to
69.76%. That shared API is rejected here; the direct component stores remain
the stronger recovered source.

## First-sweep position-materialization audit

Native writes the fixed x coordinate before completing the signed
divide-by-ten y conversion. `first-sweep-position-shape-mutations.json`
(SHA-256 `74f6c26317c034087411cfe26fbd568be2c637c649b87f52bef2ee5df340958d`)
tested reversed field order, integer and float axis temporaries, and advancing
the offset between calculation and stores. The three integer forms were
byte-neutral; the float temporary lost 3.351 weighted bytes. This rules out a
missing position-materialization idiom at the first mismatch.

## Exact-neighbor builder and later-axis audit

`builder-lifetime-interactions.json` imports the cursor/count builder recovered
exactly in neighboring `quest_build_two_fronts`, tests both field orders, and
backs the existing `spawn` and `entry_count` lifetimes with its fields through
ordinary references. The builder type alone is eliminated; the exact-neighbor
field order loses 60.31 weighted bytes when used, while the reverse order loses
75.92 bytes and one instruction. No builder-backed form improves the retained
direct lifetimes.

`second-sweep-axis-materialization.json` independently tests integer, float,
quotient, and pre-advance temporaries around the first computed-X perimeter
sweep. All four variants compile byte-identically. Together these sweeps add
12 bounded variants without a gain or tradeoff, bringing the ledger to 21
variants and four consecutive non-improving sweeps. The scratch is now
formally stalled: its residual is independent-store scheduling, not the shared
builder ABI or a missing coordinate lifetime.
