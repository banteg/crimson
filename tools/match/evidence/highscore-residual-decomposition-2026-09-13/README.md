# Highscore residual decomposition

Target: `highscore_screen_update`, native `0x004423d0`, 8,026 bytes and
2,004 instructions. Baseline commit: `8e65f70a404a86b12e6372ff1ad6280f229bc229`.
This investigation produces one local correctness fix, not a full match.

## Retained signed date conversion

Native `0x0044345d` sign-extends the date-filter byte before storing the list's
selected index. The reconstructed unsigned-byte load interpreted `0xff` as 255
instead of -1. An explicit `signed char` conversion restores this behavior.
Valid filter values 0 through 3 are unchanged; the modern port is untouched.

`verify.py` force-compiles the pinned baseline and canonical source, then runs
the original and both compiled conversion/color-setup windows in Unicorn for
all 256 input bytes. It verifies the selected index, four color arguments,
stack depth, interface pointer and vtable pointer before the color call. The
fixed code agrees with native for every byte; the old code differs on 128.
This is a bounded execution proof, not an execution test of the whole UI.

Both candidate bodies remain 7,894 bytes. All **7,848 bytes and 643 relocations
outside candidate `0x1015..0x1043` are unchanged**. The native window's instruction
order/register allocation still differs. Whole-function status is
1,968/2,004 instructions, prefix 45, references 594/0/4, 78.499496%, normalized
and encoded non-exact. The removed instruction was part of the wrong unsigned
conversion; a narrower instruction-count gap would not justify retaining it.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/highscore-residual-decomposition-2026-09-13/verify.py \
  --out /private/tmp/highscore-date-proof
```

Unicorn needs local JIT permission on macOS. The verifier patches only the
candidate window's three audited absolute relocations to their native addresses.
It does not replace any instruction or intercept the conversion.

## Separated unresolved problems

| Native region | Evidence | Result / next constraint |
| --- | --- | --- |
| `0x004424a6`, opening panel | Native panel at frame -64; current object at -72. | Splitting later tooltip lifetime moves storage but does not recover native ownership. |
| `0x00442b4d..0x00442c79`, score rows | One loop entry; separate Rush/Quest formatting arms; flags-anchored record cursor. | Pretested `while` plus `if` dispatch removes rotation and restores the earlier shared Quest constant. Rank allocation, record-cursor anchor and call tails remain wrong. |
| `0x0044300c..0x0044303e`, tooltip origin | Native copies both position words before adjusting x/y. | Explicit aggregate copy recovers four operations but disrupts other allocation/reference alignments. |
| `0x004431b8..0x0044328a`, right-panel handoffs | Chained vector sum, two aggregate copies; final y adjustment before x. | Combined source recovers this operation sequence after ignoring stack homes; that diagnostic is not acceptance. |
| `0x0044340b..0x0044353a`, filter coordinates | Native label y is `y + 114 - 14` or `y + 70 - 14`, using 32-bit constants. | Folded offsets omit native arithmetic. Restoring float expressions introduces unwanted intermediate reuse/spills. Double expressions use the wrong 64-bit operands. |
| `0x004435cb..0x00443889`, remaining filters | Item array initialized before static guard; several distinct coordinate lifetimes. | Native slot reuse is mapped below; direct temporary arguments, vector sums, explicit float casts and SDK type forms do not by themselves recover it. |

The best tested pretested-loop control reaches 80.181315%, but has 1,967
instructions and references 595/0/5. It stays private to the evidence: the score
increase does not settle the additional reference mismatch or recover the row
body. Historical negative results for isolated `if` spellings do not establish
that dispatch form is wrong when loop entry also changes.

## Compiler storage evidence

`trace_layout.py` observes the stock allocator at C2 RVA `0x33b7b`, entered from
`0x583fc`, alongside the existing preserving trace. Normal compile, captured
compile, replay and observed replay agree as whole COFF objects except timestamp;
missing-stream replay is rejected. No compiler decision is changed. The retained
`compiler-layout.json` records source uses, object sizes, frame offsets and the
trace receipt. Raw arena addresses are omitted from the summarized objects.

`frame_map.py` independently propagates ESP over every native and candidate
instruction using the checked-in Grim virtual-call ABI, cdecl direct calls and
stdcall `Sleep`. Both CFGs reach every instruction, have no conflicting join
depths and return at entry stack depth. This target-specific diagnostic exposes
storage offsets, not variable identity or semantic equivalence. Frame offsets
are relative to entry ESP; the local allocation itself is 132 bytes.

| Source role | Native frame offset | Baseline compiler offset |
| --- | ---: | ---: |
| Main position | -132 | -132 |
| Opening panel / later tooltip | -64 | -72 |
| Separator / checkbox / scrollbar / back / notice | -104 | -100 |
| Right panel | -120 | -120 |
| Online / profile / date widget | -96 | -108 / -108 / -64 |
| Player-count widget | -72 | -120 |
| Game-mode widget | -120 | -88 |
| Player-count item array | -88 | -64 |
| Date / game-mode item arrays | -40 / -20 | -40 / -20 |

Equal native offsets do not prove that the original source reused one variable.
For example, deliberately reusing the right-panel object for the last widget
changes its escape behavior and does not reproduce the native code.

## Replay controls

`controls.json` contains all 66 completed source controls, their exact edits
against the pinned baseline, source/body hashes and native matcher results.
Controls were run in successive bounded families; they are not an exhaustive
cross-product. One indexed-source generator initially damaged a declaration;
that failed generation was corrected before its controls were measured. No
compile failure is counted as negative evidence against a valid source form.

```sh
uv run --no-sync python \
  tools/match/evidence/highscore-residual-decomposition-2026-09-13/replay.py \
  --out /private/tmp/highscore-controls \
  --select '^(date-signed|row-while-pointer|widget-labels|sdk-current)$'
uv run --no-sync python \
  tools/match/evidence/highscore-residual-decomposition-2026-09-13/frame_map.py \
  /private/tmp/highscore-controls/baseline
uv run --no-sync python \
  tools/match/evidence/highscore-residual-decomposition-2026-09-13/trace_layout.py \
  /private/tmp/highscore-controls/baseline /private/tmp/highscore-layout
```

Use `--select '.*'` for every source control. The trace output directory must
not exist. The remaining work is to resolve the row cursor/rank/call lifetimes
and the filter coordinate materializations, then revisit the frame map with
those corrected flows. None of these diagnostics changes native acceptance.
