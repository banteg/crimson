# Spiders Inc. count lowering

## Exact source recovery (2026-09-11)

The current scratch is **105/105 instructions, 8/0/0 references, normalized exact,
and relocation-aware body-byte exact**. It constructs metadata before the first
record pointer, publishes it through explicit fieldwise assignment, and repeats
`step_count / 2 + 3` in the second record's setter. This follows the exact
Lizquidation builder pattern. The compiler shares the arithmetic and emits the
native `SAR EAX` / `LEA EBP, [EAX+3]` sequence and store schedule.

The [72-control source matrix](../../scratches/quest_build_spiders_inc/metadata-recomputed-count-2026-09-11.json)
contains 12 exact forms. The [one-change cache control](../../scratches/quest_build_spiders_inc/exact-count-cache-control-2026-09-11.json)
replaces only the second count expression with `wave.count` and regresses to
75.829384%, 106 instructions, and prefix 17. The earlier metadata matrix reused
`wave.count`; it did not test the successful combination.

The compiler traces below concern the pinned historical candidates, not this
exact source. They identify mechanisms behind those earlier failures without
claiming original-source uniqueness.

## Historical early-field versus scalar count

The historical early-field source and a scalar-count control diverge before
local register allocation. This observer identifies that boundary without changing compiler
decisions. Neither source is an exact match.

The pinned `early-field.cpp` source initializes `wave_count` through the first entry's count
field. The control computes the scalar at the same source position, then stores
it after that entry's trigger time. The verifier generates this control from the
pinned historical source; it does not install either control as the scratch.
The existing `canonical` label in the trace and receipt refers to that saved
early-field baseline, not the current scratch.

Four snapshots follow the original division and addition node identities:

| Observation | Canonical early field assignment | Late scalar assignment |
| --- | --- | --- |
| Before C2+0x281cd | Addition destination operand kind 2 | Addition destination operand kind 1 |
| Before C2+0x2930f | Addition opcode 0x16d | Addition opcode 0x16d |
| After C2+0x2930f | LEA, opcode 0x12 | ADD, opcode 0x2d |
| Before C2+0x336f4 | Division and addition have distinct destination storage owners | Division and addition share a destination storage owner |

This rules out attributing the whole difference to the later physical-register
choice. It does not identify the original source, prove the operand-kind
difference is the sole cause, or establish that any source family is exhausted.
The first snapshot is before the named pass, not the beginning of C2 execution.

Three additional callsite observers narrow the decision inside C2+0x2ac94.
By this point both additions have kind-1 destination operands, so their earlier
kind difference alone does not describe the instruction-selection test. The
canonical destination's symbol has a null definition link at offset `+0x14`;
the scalar destination's link points to the addition itself. Both base operands
have distinct symbols with non-null definition links, and both addends are 3.

The tests at C2+0x2ba0a..0x2ba7f send those states to different paths. The
canonical addition reaches the LEA constructor call at C2+0x2ba57. The scalar
addition reaches C2+0x2ba97 with opcode `0x16d`, then C2+0x2bac1 with opcode
`0x2d` (ADD). The verifier checks these operand states and callsite sequences,
as well as unchanged whole-COFF output. This identifies a narrower compiler
decision; it does not supply a source reconstruction that matches native.

The earlier C2+0x130cb pass explains how those states arise. Both additions
enter it with kind-1 destinations and definition links to themselves. Inside
the pass, C2+0x11209 converts both destinations to kind 2. The later
C2+0x5b30 traversal restores only the scalar destination to a temporary with
a definition link.

At C2+0x5bf5, the verifier follows the arithmetic result's direct consumers
in both backward traversals. The scalar result has one: its copy to
`wave_count`. The canonical result also feeds the first entry's count store.
C2 remembers the local copy, then clears that record when visiting the extra
field store. It therefore reaches the canonical addition without the remembered
use needed for the temporary rewrite. The scalar's remembered copy survives.
Both executions pass the same whole-COFF equality checks; none of these
observers changes an operand or an optimization decision.

This makes the next source question more specific: how to preserve the native
separate arithmetic result while publishing the count at the native position.
It does not establish that another local declaration or helper will do so.

Run from the repository root:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-spiders-count-2026-09-10/verify.py \
  --out /private/tmp/c2spiders-count-proof
```

For each source, the verifier checks normal, captured, replayed, and observed
whole-COFF equality with only the COFF timestamp excluded. It also requires the
missing-stream negative control to fail and the observed match metrics to equal
the normal build. The observer preserves registers and flags, validates each
hook's original call target, and reads the instruction list and operands.
The phase snapshots, address-folding decisions, and count-use records are written
separately to `phases.bin`, `decisions.bin`, and `uses.bin`.

The recorded historical early-field result is 96.1905%, 105/105 instructions, with seven
clean aligned references. The scalar control is 75.8294%, 106/105 instructions,
also with seven clean aligned references. Both normalized exactness and
relocation-aware encoded-body exactness are false. New source matches: **0**.

## Historical candidate: delayed count publication

The pinned `delayed-count.cpp` computes `wave_increase = step_count / 2` once and adds the
base count at each row's count store. Each row now publishes coordinates,
template, trigger time, and count in the native order. The prior early-field
candidate published the first row's count before its coordinates.

That historical result improved **96.190476% to 97.630332%**, prefix **57 to 58**,
and clean aligned references **7 to 8**. It has **106 instructions against 105**
native instructions, whereas the previous candidate had 105. This instruction
count tradeoff is explicit: normalized and encoded-body exactness remain false.
The remaining arithmetic lowering includes an extra `MOV` and an in-place
`SAR`/`ADD` where native uses `SAR` followed by `LEA`; its scheduling still differs.
No compiler decision, alias, or exact-match acceptance rule is changed.

## Current exact candidate: publication verification

[`verify_publication.py`](verify_publication.py) requires both exactness checks,
links the real COFF relocations, and executes both machine bodies with Unicorn
2.1.4. For each of 15 signed,
zero, odd, even, and representative terrain widths, it checks all 33 records
against an independent field-level oracle, including untouched heading words
and surrounding sentinel bytes. It compares the full sequence of 166 output
writes, checks stack balance and callee-saved registers, and requires every
instruction in each body to execute. The historical early-field source gives
the same output bytes but fails the native publication-order comparison in all
15 cases, beginning at the first generated wave's count store.

The [publication receipt](publication.json) pins the source, verifier, image,
native body, candidate object/body, compiler inputs, and relocation resolution.
These are bounded executions with disjoint output, count, and global storage
and x87 control word `0x037f`; they do not establish equivalence for every input
or alias arrangement. Whole-function exactness is checked separately by the
matcher in the same run.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/vc6-spiders-count-2026-09-10/verify_publication.py \
  --out /private/tmp/spiders-publication
```

Unicorn needs JIT execution permission. The count-lowering observer above
remains separately reproducible from its saved historical source and continues
to check unchanged observed COFF objects.

## Historical candidate: division-copy lifecycle

[`verify_half.py`](verify_half.py) observes the pinned `delayed-count.cpp` independently of
the historical comparison above. The [receipt](half.json) follows instruction
identity through eight backend snapshots. It compares the wave quotient with
the first generated row's terrain midpoint, both ordinary signed divisions by
two in the same function.

At `C2+0x29511`, each division becomes the signed-halving sequence and gains a
copy from EAX to its result temporary before `SAR`. This happens before global
register allocation. Across `C2+0x2fb58`, the wave quotient is assigned EBP;
across `C2+0x336f4`, the midpoint quotient is assigned EAX. Both copies remain
present immediately before `C2+0x3536c`. Across that call, the midpoint's
`EAX -> EAX` copy disappears, while the wave's `EAX -> EBP` copy survives. The
latter still exists after instruction scheduling at `C2+0x374aa`.

Thus the extra wave copy is introduced during division lowering and survives
allocation and cleanup; it is not first inserted by the final scheduler. This
observation narrows the compiler mechanism without identifying original source
that would recover native `SAR EAX` followed by `LEA EBP, [EAX+3]`.

The verifier requires normal, captured, replayed, and observed whole objects to
agree except for the COFF timestamp, and includes the missing-stream negative
control. It pins the historical source, compiler, observer, and replay helpers;
all eight references remain clean. No compiler decision is modified, and both
exactness flags remain false. No new source match is claimed.

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-spiders-count-2026-09-10/verify_half.py \
  --out /private/tmp/c2spiders-half-proof
```
