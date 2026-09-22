# Highscore floating-expression reuse

The canonical source has a finite-input arithmetic mismatch, and the cumulative
row/filter witness introduces a different rounding boundary. Neither is a
whole-function match. This package identifies the compiler decision responsible
for the witness's extra store and retains source controls that do not recover
the native sequence. The canonical body is unchanged; its recovery declaration
is corrected to `incomplete`, with `analysis` restored to its residuals.

## Native and candidate behavior

Native prepares the profile label at `0x44340b..0x44342d` as
`(Y + 114) - 14`, with a single float32 store after both x87 operations. It
recomputes `Y + 114` after the drawing call for the profile widget. The canonical
source instead uses `Y + 100`. The cumulative `row-plus-widget-labels` witness
restores the two operations, but C2 saves `Y + 114` to float32 before subtracting
14 and reuses the saved sum after the call.

For `Y = 0x41800003` (approximately 16.0000057), round-to-nearest gives:

| x87 precision | Native argument | Canonical `Y + 100` | Cumulative saved sum | Scoped deny-both diagnostic |
|---|---|---|---|---|
| 24 bits | `0x42e80000` | `0x42e80001` | `0x42e80000` | `0x42e80000` |
| 53 or 64 bits | `0x42e80001` | `0x42e80001` | `0x42e80000` | `0x42e80001` |

These values differ by one float32 ULP. The second counterexample is
`Y = 0x41800004`. A higher alignment score or choosing one precision setting
does not establish equivalence.

`verify_execution.py` executes native, canonical, cumulative, and deny-both
label setup for 239 finite inputs under all 12 combinations of x87 precision
(24/53/64) and rounding direction. All **2,868 fixtures** agree with independent
exact-rational models of their respective operation/store sequences. There
are 11,472 instruction-window executions. Mismatch counts against native are:

| Precision | Rounding | Canonical | Cumulative |
|---|---|---:|---:|
| 24 | nearest / down / up / zero | 2 / 9 / 12 / 9 | 0 / 0 / 0 / 0 |
| 53 | nearest / down / up / zero | 0 / 0 / 0 / 0 | 2 / 9 / 12 / 9 |
| 64 | nearest / down / up / zero | 0 / 0 / 0 / 0 | 2 / 9 / 12 / 9 |

The test stops before the virtual draw call. It checks X, Y, string pointer,
interface/vtable registers, stack balance, and empty x87 stack. Four candidate
references resolve against native operand identities. The canonical 100.0f
reference additionally resolves against native `0x442a6a` and its checked
constant at `0x46f2c4`. Instruction, constant, and stack-binding corruptions are
rejected. This proves the bounded argument behavior, not full UI execution,
actual gameplay reachability of every fixture, or the runtime FPU state.
The date label is covered by compiler tracing, not this execution test.

## C2 decision

The compiler is pinned to `msvc6.5`, C2 SHA-256
`d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`.
The cumulative source is reconstructed from the preceding filter-storage
package and pinned to SHA-256
`ffc2226e2ec54cefaf4a2fde09fd1f379342b105f9162a418b49f5d0ce1fa6c7`.

1. The call at C2 `0x13189 -> 0x11209` changes the two separately computed
   profile additions from distinct kind-1 temporaries to the same kind-2
   expression owner. The date pair behaves identically. Pointer identities
   are compared only within one event; arena addresses are not stable names.
2. In optimizer phase 3, C2 `0x9739 -> 0x251d` tests the expression's available
   bit. The profile widget addition (function-relative source line 401) returns
   32768, and the date widget addition (line 426) returns 2. Their expression
   bit indices are 2127 and 2145 in this pinned trace.
3. C2 `0x97a4 -> 0x210e` deletes each redundant addition. The observer checks
   opcode `0x16d`, source line, expression fields, instruction identity, phase,
   return value, and deletion sequence.
4. Changing only either selected nonzero availability return to zero prevents
   its deletion. The installed compiler is untouched; these changes exist
   only in replay observers.

The preserving observer produces the same **whole COFF except timestamp** as
the uninstrumented compiler. Missing frontend streams are rejected. Seven
corrupt trace/model controls are also rejected.

| Denied reuse | Instructions | Frame | References ok/unresolved/mismatch |
|---|---:|---:|---|
| Neither | 2005 | 132 | 604/0/6 |
| Profile | 2004 | 132 | 601/0/6 |
| Date | 2004 | 128 | 592/0/13 |
| Both | 2003 | 128 | 589/0/13 |

The deny-both profile-label setup has exactly the native 34 bytes after four
audited relocations and the single Y stack binding (`0x34 -> 0x20`). This is a
local diagnostic identity, **not a stock-source recovery**. The surrounding X
copy, player-coordinate reuse, frame allocation, references, and other regions
still differ. Both whole-function exactness flags are false in every control.

## Source controls and stop rule

`controls.py` rebuilds canonical and cumulative sources plus 12 additional
controls, checking their source/body hashes and measured results:

- A borrowed Y component and four union member/array access forms are
  body-byte neutral to the cumulative witness.
- Borrowed scalar constructor arguments change other code but retain the
  unwanted save/reload. Copying the vector before adjusting it, including
  adjusting only Y, does not recover the native ownership.
- Subtracting negative 114/70 in either labels or widgets prevents reuse but
  emits `FSUB` with negative constants where native has `FADD` with positive
  constants.
- Casting either side's Y base to double prevents reuse but emits qword
  arithmetic constants where native uses dword constants.

An additional `/Op` compiler-flag check also retains the cumulative profile
label's intermediate float32 save/reload. It produces 2,029 instructions
(canonical under `/Op`: 2,022), versus native's 2,004. It is not a recovery
control. After rebuilding the sources with the commands below, reproduce this check with
`crimson match probe tools/match/scratches/highscore_screen_update --source /tmp/highscore-float-controls/baseline/scratch.cpp --cflags '/O2 /GB /W3 /GR- /Op'`.

Do not repeat these spellings as untested recovery ideas. A useful next source
control must explain why the two native dword additions remain separately
available without introducing an extra rounded store, wrong operation, wrong
constant width, or changed call argument. The cumulative source's X ownership
and stack placement remain separate constraints.

## Replay

Run from the repository root with fresh output directories:

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python tools/match/evidence/highscore-float-reuse-2026-09-22/controls.py --out /tmp/highscore-float-controls
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python tools/match/evidence/highscore-float-reuse-2026-09-22/verify_compiler.py --out /tmp/highscore-float-compiler
uv run --offline --no-sync --with unicorn==2.1.4 python tools/match/evidence/highscore-float-reuse-2026-09-22/verify_execution.py --compiler-proof /tmp/highscore-float-compiler --out /tmp/highscore-float-execution
```

The checked-in receipts are `compiler-results.json` and
`execution-results.json`. Raw observer traces and objects stay in the replay
directories. The compiler proof validates complete COFF preservation; the
execution proof additionally binds its inputs to that compiler receipt.
