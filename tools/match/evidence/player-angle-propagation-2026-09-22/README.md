# Fire Cough angle propagation and alias interference

The remaining angle schedule in `player_update` has two coupled compiler
causes. C2 first propagates the named heading into the projectile argument.
That move crosses a position write, which then prevents propagation of the
angle's two input loads. Preventing the heading move alone removes that
obstacle and reverses the emitted input order.

**No source change is selected and no new match is claimed.** Canonical
`player_update` remains 4,070/4,206 instructions, prefix 7, references 807/0/2,
with both exactness flags false. Source SHA is
`c982bef1d0b1aa82f7aa2f2488fbe0df72959e8d9ffa31f9a69f89762234a72c`.
The compiler interventions below are diagnostic outputs, never candidates.

## Native constraint

After `vec2_sub` at `0x413b7f`, native loads `[eax]` (X), then `[eax+4]` (Y),
uses `fxch`, and executes `fpatan`. It prepares the owner, point pointer and
type arguments before `fsub` and the heading store at `0x413b9e`. The store
uses entry-relative home −48, also previously used by subtraction-output X.
Only then does native add the projectile position. Reuse of a physical home
alone does not establish that the original source reused one variable.

The canonical candidate retains X/Y/`fxch`, but performs the position adds
and stores before `fpatan`, and writes the heading directly to outgoing
argument home −100. These are distinct constraints: computation order,
input order, subtract scheduling and storage ownership.

## Observed decisions

The preserving observer is pinned to C2 SHA
`d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`.
Its whole COFF equals an ordinary compile after clearing only the timestamp;
the standard capture also rejects the missing-stream control.

At `C2+0x1315a -> 0x11afa`, three line-171 float definitions are identified:
X and Y parameters of the inlined `atan2f` wrapper, then `shot_heading`.
The verifier follows their operand producer chains to distinguish `[p]` from
`[p+4]`. Line labels are relative to the function, not physical file lines.

1. `C2+0x11f08 -> 0x11786` accepts each definition/use pair. This helper
   checks control-flow/scope eligibility; it is not the alias predicate.
2. `C2+0x1273e -> 0x1d548` moves the heading expression to its line-181
   argument use. `C2+0x12794 -> 0x211e` removes the original assignment.
   The intrinsic changes from before the Y/X position adds to after them.
3. C2 then considers propagating the X and Y input definitions. The
   expression checks at `0x12713 -> 0x42ad4` pass, but the crossing checks
   at `0x125d8 -> 0x42ad4` fail for both.
4. Calls from `0x42b47 -> 0x2771` identify the actual blocking operand pair:
   the destination of the line-174 `move_delta.x` store and the indirect
   input read. The positive conflict is recorded for each input. This is
   the compiler's possible-alias result, not a claim that the runtime
   objects actually overlap.

The observer records all three operand-comparison callsites inside `0x42ad4`,
not just the first positive result. It also records when adjacent definition
and use let C2 skip the crossing scan. Arena addresses are correlated only
inside one replay with opcode/symbol checks. C2 immediately recycles a deleted
input node as a conversion node in one control, so pointer absence would be
an invalid test for assignment removal.

## Controlled interventions

A three-bit mask denies only the observed eligibility results for X, Y and
heading respectively. Every original result is asserted to be 1; enabled
bits change it to 0. There are eight modes including the disabled observer.

| Denied definitions | Result |
| --- | --- |
| None; X; Y; X+Y | Whole COFF identical to canonical. The heading still moves; enabled input denials add no emitted change. |
| Heading | Both input assignments propagate; heading stays early, but loads become Y then X with no `fxch`. |
| X+heading | Only Y propagates. Early heading computation and X/Y/`fxch` coexist, but subtract scheduling and the heading home still differ from native. |
| Y+heading | Only X propagates. Early heading remains, with Y/X loads. |
| X+Y+heading | None of the three assignments propagate here. Later passes still emit Y/X loads and a different store/argument schedule. |

This rejects the idea that keeping the angle early is sufficient, or that
preserving both wrapper assignments necessarily preserves final X/Y loading.
It does not establish a stock-source way to produce native's full sequence.

Nine ordinary builds comprise baseline and eight source controls. A separate
one-element array, struct, union, double destination with `atan2f`, and moving
the scalar's subtract into the call argument are all whole-COFF neutral.
Writing the angle into the existing scratch vector gives early storage but
Y/X loads. Putting that member's subtract in the argument adds a store/reload;
a const-reference angle with argument subtraction also misses the native
sequence. These controls are not selected. Earlier returned-pointer,
reference, value-vector and storage controls remain documented in the
[Fire Cough](../player-fire-cough-2026-09-14/README.md) and
[Hot Tempered](../player-hot-tempered-2026-09-14/README.md) packages.

## Reproduction and limits

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/player-angle-propagation-2026-09-22/verify.py \
  --out /tmp/player-angle-proof
```

Use a fresh directory. `results.json` retains the preserving manifest,
source/object hashes, complete native/candidate angle windows, decision
summaries, seven rejecting corruption controls, and all eight intervention
modes. Generated raw traces, objects and annotated assembly stay in the output
directory. All ordinary builds and diagnostic objects have full static ESP
propagation, no conflicting joins, and balanced returns.

No new runtime-equivalence claim is made. The unchanged canonical candidate's
older finite execution proof remains separate. The unresolved source problem
is now narrower: explain early heading ownership while independently retaining
the X-input lifetime, then account for subtract scheduling and the physical
home. Repeating standalone scalar/aggregate renamings does not address those
constraints.
