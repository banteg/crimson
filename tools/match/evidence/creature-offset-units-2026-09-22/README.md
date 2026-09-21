# Creature offset units and pointer retention

`creature_update_all` does not have one undifferentiated “allocation cascade.”
A preserving C2 trace and four controlled replays separate two decisions:
address units chosen before allocation, and repeated elimination of a named
health pointer. Correcting the first in diagnostic IR does not recover the
native frame or preserve every previously recovered observation.

Canonical source remains unchanged: 1,306/1,338 instructions, 124-byte frame,
58.547655%, prefix 10, 226 aligned references with one problem, non-exact.
No compiler intervention earns source, provider, or match credit.

## Shared offset: before allocation

Native opens with two LEAs computing `19 * creature_index` and uses
`[esi*8 + creature_field]`. The candidate computes the same two LEAs, then
`shl esi,3`, and uses `[esi + creature_field]`. The structure is still 152
bytes; its layout is not the variable to change.

| Observed boundary | Candidate representation |
|---|---|
| Before `C2+0x130cb` | Separate index-times-152 expressions |
| Before `0xfcda` and `0x281cd` | One shared index-times-152 value, 105 additions to field addresses |
| After `0x281cd`, before `0x2930f` | Multiplications/additions implementing 9i, 19i, then 152i |
| After `0x2930f`, before `0x29511` | Two LEAs, shift by three, and copy into shared offset |
| Before `0x2f8fc` allocation driver | The same shift is already present |
| Before `0x336f4` | Shift assigned to ESI; byte-offset addressing remains |

The verifier discovers the shared symbol from its definition inside each
snapshot, rather than relying on a process-specific address. All 105 uses
are address construction; none consumes the shared byte count as scalar data.
This establishes the candidate's pass history, not the unavailable native
source's compiler history.

`rescale.c.in` controls the unit choice immediately before `0x29511`. It
replaces the final shift with a copy and gives all 105 address operands an
index scale of eight. One definition, every use, and every address replacement
are counted and checked. Address operands are rebuilt with C2's index-only
form (`0x14f`), keeping displacement, symbol, and the actual index operand.
The two-operand form (`0x14d`) is not interchangeable with this form. The
installed compiler and emitted object bytes are never patched.

The transformed address expressions have the same value: `base + 152*i`
and `base + 8*(19*i)`. That algebra alone does not establish the behavior of
all subsequent compiler transformations; emitted code and execution are
checked separately.

## Health pointer: more than one removal opportunity

The source's health-pointer assignment is still present as LEA/COPY before
`C2+0x306c1`, and absent immediately afterward. Inspection of that routine
shows descriptor byte `+5`, bit 4 excludes a value from substitution; the
routine itself clears this bit before returning.

`retain.c.in` sets that bit only on the health-pointer destination found at
function-relative line 27. The LEA survives the pass, but is absent by the
post-allocation boundary. The final whole COFF is identical to the corresponding
unmodified-retention control, excluding timestamp bytes only. This holds both
with the original byte offset and with the scaled-offset intervention.

This experiment does not locate the second deletion within the intervening
passes. The timeline's previously identified `0x32216` is a useful lead, not
proof that this creature pointer takes that same route. A new local variable
or suppressing only the first substitution is insufficient.

## Four controls

| Offset units | Health control | Frame | Instructions | Health after `0x306c1` | Final object |
|---|---|---:|---:|---|---|
| Bytes | Disabled | 124 | 1,306 | Absent | Stock-identical |
| Bytes | Retain for one pass | 124 | 1,306 | LEA retained | Stock-identical |
| Eight-byte units | Disabled | 112 | 1,304 | Absent | Diagnostic only |
| Eight-byte units | Retain for one pass | 112 | 1,304 | LEA retained | Identical to scaled control |

Scaled addressing appears in the emitted opening, but the native frame is
124 bytes, not 112. The diagnostic score rises to 64.193793% while the aligned
reference problems rise from one to ten. These alignment-dependent numbers
are diagnostic context, not evidence of correctness or reference ownership.

## An already-correct animation detail regresses

All **3,480** existing execution fixtures reproduce native observations with
the canonical candidate. They include 2,472 historical cases, 768 retarget
boundaries, 192 interaction boundaries, and 48 corpse cases, using the existing
explicit callback models and Unicorn 2.1.4.

The scaled diagnostic preserves final state, players, slots, scalars, modeled
callback writes, and calls in all those fixtures. Two cases differ in the
ordered game-memory write trace: `animation-wrap-4-pc37f` and
`animation-wrap-4-pc07f`.

For animation phase 94, flags 4, and movement speed 1.7, both code paths first
store approximately 94.448799. Native and canonical code perform repeated
subtraction of 15 in x87 and store approximately 4.448799 after the loop.
The scaled diagnostic instead stores approximately 79.448799, 64.448799, etc.
on every iteration: five extra stores, with the same final value in these
fixtures. The emitted canonical loop retains ST(0) across its backedge; the
scaled loop reloads the field at the backedge and stores inside the loop.

This is a concrete loss of recovered instruction/write staging despite the
higher score. Finite fixture agreement on final state does not establish
whole-game equivalence, nor does the write difference alone prove a gameplay
bug for ordinary nonvolatile memory. The separate callback-mutation suite is
not rerun here, and the diagnostic is not a source candidate.

## Next discriminating work

- Find why the original frontend/optimizer representation retained the offset
  in eight-byte units. The candidate's shift is too early to blame on its final
  ESI assignment or stack layout.
- Follow the retained health definition and its consumers through the remaining
  passes; identify the second removal predicate before trying to control it.
- Track the animation memory value through x87 loop promotion. Any source
  recovery must satisfy scaled addressing, pointer lifetimes, the 124-byte
  frame, and this existing loop staging together.

These are measured constraints, not a claim of source exhaustion.

## Reproduce

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/creature-offset-units-2026-09-22/verify.py \
  --out /tmp/creature-offset-units
```

Use a fresh output directory. The ordinary compiler trace checks normal,
captured, replayed, and observed whole COFF equality (timestamp excluded),
compiler/source hashes, frontend streams, and missing-stream rejection. The
additional disabled intervention is stock-identical. Raw streams, complete
operand traces, objects, candidate listings, and per-fixture observation hashes
stay in the output directory. Adjacent `results.json` retains compact receipts
and the two write witnesses. No candidate source or compiler flags changed.
