# `statistics_update_check_worker`

Native target: `crimsonland.exe` at `0x0042d8a0` (1375 bytes).

Work in progress: 99.182561% normalized match, 252/367-instruction exact prefix,
367 candidate instructions, and 120/0/0 reference audit. The remaining three
instruction differences prepare the `sscanf` outputs after URL duplication;
`body_byte_exact` remains false.

Live Binary Ninja evidence and the MSVC candidate recover the complete worker:

- it posts the native two-line octet-stream header to
  `www.crimsonland.com/ra_version.php` with the 10-entry accept list, guest
  credentials, the native WinINet flags, and context `0x1289`;
- it receives 0x400-byte chunks into a zeroed 0x8000-byte buffer, preserves the
  native overflow guard, and reports both `GetLastError` and
  `InternetGetLastResponseInfoA` on a read failure;
- it accepts only a response beginning with `<a href`, splits the quoted URL
  and following `Crimsonland` label in place, duplicates the URL, and parses
  the three decimal version fields;
- the native update gate is `major > 1 || minor > 9 || patch > 94`, compared
  against the logged local label `Crimsonland 1.9.93`;
- all request, connection, and session handles are closed after the response
  buffer is deleted, then status advances through `5` and `0` on success or to
  `6` on failure, with the matching pending flag and 300 ms sleeps.

## Recorded read-loop control-flow sweep

Fresh live Binary Ninja disassembly localizes the receive-loop shape at
`0x0042daf6..0x0042dba8`. Native sends either failed `InternetReadFile`
directly to the shared diagnostic tail at `0x0042db37`, branches overflow to
`0x0042db96`, branches a zero-byte read to parsing at `0x0042dba8`, and uses
one successful backward edge for the next chunk.

`read-loop-control-flow-mutations.json` records three complete semantic
singles against the 69.9454% baseline:

- the retained conjunctive loop scores 76.8392%, adds 94.0325 weighted bytes,
  compiles 373 instructions, and improves references from `102/0/0` to
  `106/0/0`;
- a success-guarded loop scores 74.4565% with 375 instructions and the same
  `106/0/0` reference audit; and
- direct native-exit labels score 71.1354% with 370 instructions but regress
  the audit to `97/0/1`, so that more literal CFG spelling is rejected.

The winner keeps structured source while evaluating read success, the 0x8000
bound, and zero-byte completion in native order. It also makes VC6 retain the
`InternetReadFile` import in `edi`, matching both native loop calls. The plan
has one localized site, so there is no interaction space; the complete sweep
is stored in `experiments.jsonl`.

The remaining mismatch is code-generation shape rather than missing behavior.
The native frame places the reused 64-byte host/path slot below the MIME array
and lowers the 15-byte path initializer into individual stores; MSVC gives the
typed candidate the opposite array-slot order and four literal loads. It also
tail-merges the four native WinINet failure messages and orders the three scan
outputs differently. Natural scope, initializer, failure-label, and MSVC 6.6
variants were tested; the retained source now also incorporates the proven
structured read-loop improvement while avoiding padding, byte-by-byte source
spelling, volatility, or artificial register constraints.

The former unresolved `_sscanf` relocation is now scoped to native
`crt_sscanf`. Live Binary Ninja shows the sole call from this worker, the
native cdecl varargs wrapper, and its handoff to the CRT scanning core; the
callsite passes the recovered `Crimsonland %d.%d.%d<` format and three integer
outputs. The alias therefore resolves the same callee rather than masking an
unknown reference.

## Semantic-completion audit

Fresh live Binary Ninja HLIL confirms the request construction, bounded read
loop, nested response parser, three-field version gate, cleanup ordering, and
both status-transition tails. Address-matched IDA and Ghidra snapshots agree
on the worker signature and all 18 direct callees. The retained candidate is
reference-clean at `106/0/0`.

Earlier isolated MIME-array and version-output declaration moves were
byte-identical. An explicit shared host/request-path buffer instead regressed
from 69.95% to 66.04%, removed the then-current exact prefix, and introduced a
reference mismatch. The scratch remains classified `semantic-complete` with a
`compiler` residual.

`request-path-initializer-mutations.json` evaluated three direct, aggregate,
and staged request-path initializers. Every alternative regressed by at least
57.76 fuzzy-weighted bytes and lost native-prefix or reference agreement. The
existing initializer is retained.

## Native-grounded declaration and lifetime wave

Fresh normalized target/candidate listings localized the earliest residual to
the prologue. Native evaluates the header length before allocating the response
buffer but stores it after other scalar setup, places the reused 64-byte
host/path slot below the MIME array, and later closes the connection and
internet handles through the opposite pair of stack slots from the candidate.

`scalar-declaration-order-mutations.json` evaluated ten complete declaration
orders. All ten forms that moved the already-computed header length after the
scan-output declarations compiled identically and improved by
`3.716621253405947` weighted bytes, extended the prefix from 21 to 22
instructions, and moved the first mismatch from byte `0x4b` to `0x50`.
The retained source makes only that minimal declaration move.

`accept-array-lifetime-mutations.json` then evaluated all five single and
paired forms for moving the MIME list into the request scope. Declaring the
list immediately before `request_path`, with or without retaining the dead
outer declaration, improved by another `3.716621253406174` weighted bytes.
The retained source uses the non-duplicated scoped form. Candidate/native
instruction counts remain 373/361, the prefix remains 22, and the reference
audit remains clean at 106/0/0.

Four follow-up hypotheses reached bounded stopping points:

| plan | variants | result | SHA-256 |
| --- | ---: | --- | --- |
| `network-stack-lifetime-mutations.json` | 5 | scoped form neutral; shared or simultaneous buffers worse | `3c8c1ccbb4bf2638fe0d89812e78684bf94fe69157de964bd60a8a1d83e5778c` |
| `network-failure-tail-mutations.json` | 63 | declaration neutral; shared-tail interactions invalid or non-improving | `2e992997ab568d6da6488bb126de5cf4e9f04a1a7fd9cda16a180bb9bcc27c4f` |
| `server-address-lifetime-mutations.json` | 3 | outer lifetime neutral alone and worse when active | `9fe3c700d7fa18cee0150f656399fd9ef0f4d4464a9fcd55c4124304a2079226` |
| `read-loop-second-wave-mutations.json` | 8 | two byte-neutral spellings; six worse | `420d15c8e340bc8a59a53e3473f94a56675811f7a8f45df174c1429e1d302716` |

The two improving plans have SHA-256
`31c176e6ed793bbb015fad5cd8616f24e9caa08858728510f8ac1eaaa5eab0a5`
and
`d80b786d5812c7ab6e49c1328042ce60be95d8084f4d8d2c44720249aae0b059`.
Together the wave evaluated 94 new variants and reduced the gap from
`315.9128065395096` to `308.47956403269745` weighted bytes. The complete
nine-plan corpus now contains 102 unique variants with no repeated
evaluations. The retained source SHA-256 is
`fbcccb4047061ffcc135469c9d4db4f5df475fd424a4456258d36e2a466d642c`;
`experiments.jsonl` is
`7a2afd319355c070ab2636aa9acc48cc669a13c43aa6bbf0c16f1836f9a287e8`.

## Native worker extent correction

The canonical function extent ended at `0x0042ddf4`, immediately after the
`crt_endthread` call, but live Binary Ninja disassembly shows that the same
native function continues through the ordinary VC6 epilogue at
`0x0042ddf4..0x0042ddfe`. The neighboring network worker
`highscore_sync_worker` uses the same house style: its `crt_endthread` call at
`0x0042d88d` is followed by register restores, stack release, and `ret` through
`0x0042d89c`. The candidate already emitted the corresponding six
instructions; they were incorrectly classified as extra because the target
was truncated.

The curated function map now overrides the stale analyzer extent with
`end=0x0042ddff`, so every matcher and coverage consumer includes those eleven
native bytes without a scratch-local exception. This raises the measured
result from 1,055.520435967303/1,364
(77.384196185286%) to 1,077.702702702703/1,375 (78.378378378378%), reduces
the fuzzy gap from 308.479564032697 to 297.297297297297 bytes, and changes
the instruction comparison from 373/361 to 373/367. The prefix remains 22
and references remain `106/0/0`. Source is unchanged at SHA-256
`fbcccb4047061ffcc135469c9d4db4f5df475fd424a4456258d36e2a466d642c`.

## Accept-array current-layout recheck (2026-08-11)

The first bounded current-layout replay tested five single and paired
hypotheses. Reintroducing a dead function-scope MIME array before or after
`response_error` is byte-neutral. Replacing the active request-scope array
with either outer lifetime regresses from `1077.7027027027027` to
`1073.9864864864865` weighted bytes (78.38% to 78.11%), while removing the
only active array is compile-invalid rather than a meaningful variant.

The retained source now documents the request-only lifetime directly. The
strict-clean current spec exhausts the two valid independent outer-declaration
probes (2/2 neutral); the original five-result record remains historical
evidence for the two coupled regressions and the rejected invalid singleton.
The scoped array therefore remains the only active declaration. The current
spec SHA-256 is
`9e925517304a4f1176fd58d4a90f196ebfdec89a9a02dbf50a64be0a5ad5dd90`;
the comment-only retained source SHA-256 is
`f395f87f40fec1c326807bc4a031dacea4c20ea122aa5b6e49c975048661dd3a`.

## Current declaration-order controls

Two strict current-epoch sweeps test whether the residual worker stack layout
comes from otherwise independent declarations. The
`version-output-order-mutations.json` plan exhausts the five other permutations
of the major, minor, and
patch output locals. `handle-declaration-order-current-mutations.json` exhausts
the five other permutations of the internet, connection, and request handles.
All 10/10 variants are byte-identical to the 78.378378%, 373/367,
`106/0/0` baseline, so declaration order is not a live lever for either group.

The complete spec SHA-256 values are
`278508252dea1ee5e78d13ccb7765ce4288e3485bdaf0f516c4755fd05fdc5a1`
and
`1012aca08a892cd83de144a52caf424709d3313864f2a546760db4db1903002c`.

## Batch 03 focused value boundaries (2026-09-05)

`batch-03-focused-value-boundaries-mutations.json` records 6 complete, compiling
controls against the 78.378378% baseline. The source forms are
`path-character-publication`, `host-character-publication`,
`both-character-publications`, `path-function-lifetime`, `shared-pre-result-delay`,
`path-and-shared-delay`.

The highest-score control, `path-character-publication`, reaches 83.845127% but is
rejected for instruction-count-further-from-target. Canonical source and configuration
are unchanged. These results bound the recorded hypothesis, not the function's
matchability.


## Network source ownership recovery (2026-09-07)

The MIME array now precedes header-length publication, and the request path is
zeroed before its individual character stores. Connection and request success
blocks share their failure cleanup. The receive loop branches directly to its
error, overflow, or parse continuation without repeating its stopping tests.
Finally, the three parsed version components share one local array. Together
these boundaries recover the native handle slots and all but the final scanner
argument scheduling. Request bytes, parsing rules, and status transitions are
unchanged.

The complete 31-control `network-source-ownership-2026-09-07.json` crosses all
five changes. Every control compiles. The retained combination improves
78.378378% to 99.182561%, removes six surplus instructions to reach 367/367,
extends the prefix from 22 to 252, and raises clean references from 106 to 120.
A separately recorded formatting probe preserves those metrics. The remaining
URL-store and scanner-address ordering is explicitly a compiler residual, not
an exact match.

## Version aggregate controls (2026-09-08)

The two complete plans `version-aggregate-2026-09-08.json` (7 controls)
and `version-storage-layout-2026-09-08.json` (9 controls) test named version
records, all six record orders, component arrays, three shorter array
lifetimes, pointer arithmetic, and named output-component pointers. All
16 compile; none improves the 99.182561%, 367/367-instruction, prefix-252
baseline. Array and pointer spellings are neutral; record layouts regress.
The remaining scanner-address scheduling starts at native offset `0x3b4`.
Canonical source is unchanged. These results bound only these source forms.

Four additional `version-parser-ownership-2026-09-08.json` controls move the
scanner into an inline helper receiving an array pointer, array reference,
component pointers, or component references. All four are byte-neutral with
120 clean references. The total for this follow-up is 20 compiling controls.

## URL publication and parser flag controls (2026-09-09)

Two further complete plans contain 18 compiling controls. The seven
`url-scan-boundary-2026-09-09.json` forms stage the returned URL or component
pointers, borrow the URL by reference, use a comma expression, or name the
unused scanner result. They are byte-neutral at 99.182561%, 367/367
instructions, prefix 252, and 120 clean references.

`parsed-store-lifetime-2026-09-09.json` crosses byte flag types with the flag's
publication point. All eleven planned controls compile. Signed/unsigned byte
spellings are neutral; moving the successful-parse flag across the terminator,
URL duplication, or scanner call regresses. Neither plan changes canonical
source or claims that the remaining schedule is unavoidable.

The [network micro oracles](../../evidence/network-micro-oracles-2026-09-09/README.md)
now check the differing instruction window independently. Given equal entry
states, both publish the same URL and push the same three output addresses.
The isolated VC6 array and scalar controls naturally select native's first
`lea ecx`; the full worker selects `lea edx`. This is evidence for an allocation
context difference, not proof of the original variable layout or an exact
encoded body. The full-function matching requirements remain unchanged.

## Distinct VC6 build controls (2026-09-09)

The [bounded address-allocation record](../../evidence/address-allocation-controls-2026-09-09/README.md)
compares the current source across five independently fingerprinted VC6 builds.
None improves this candidate; canonical source and configuration are unchanged.

## PCH and debug-information controls (2026-09-09)

The [compiler-context record](../../evidence/compiler-context-controls-2026-09-09/README.md)
verifies identical full-function objects across Wine and the repaired wibo
fork for plain compilation, PCH creation, and PCH reuse, normalizing only
the COFF timestamp. `/Zd` and `/Zi` also retain the baseline metrics.
The runner fixes restore PCH support but produce no matching gain; source
and canonical compiler flags are unchanged.
## Independent backend replay (2026-09-09)

The [VC6 intermediate-stream proof](../../evidence/vc6-intermediate-replay-2026-09-09/README.md)
captures this unchanged source between C1XX and C2, then replays its four streams
in a standalone backend process. Normal, captured, and replayed COFF objects
agree completely except for the header timestamp. The matcher still reports
99.182561%, 367/367 instructions, prefix 252, and 120 clean references; this
adds a compiler diagnostic boundary without resolving the register permutation.

## Exact receive-loop exit recovery (2026-09-09)

Replacing the conditioned receive loop with `for (;;)`, followed by an
explicit `if (!read_ok) break`, resolves the remaining compiler difference.
The initial read still happens once; a failed read still enters the existing
error-reporting path, while overflow and zero-byte completion retain their
original continuations. No scanner, parser, ABI, compiler flag, or reference
alias changes are involved.

The complete three-control `receive-loop-exit-2026-09-09.json` plan records
the old 99.182561% with prefix 252 baseline. Both explicit-break forms
(`for (;;)` and `while (1)`) become exact; a conditioned `for (; read_ok;)`
is neutral. The retained, formatted `for (;;)` source has 367/367 identical
instructions, 120 clean references, zero mismatches or unresolved references,
and relocation-aware `body_byte_exact=true`. Canonical direct matching and
the independent frontend-capture/backend-replay proof both verify the result.

For the statistics worker, an observer trace of VC6's forward register
assignment pass explains the distant scanner improvement. The explicit exit
places the receive-error address temporaries before parser temporaries in
the pass's traversal. Its shared allocation cursor then assigns the scanner's
three addresses to ECX, EDX, and EAX, matching native. The trace preserves the
entire compiled object except its timestamp. This observation is specific to
the statistics worker; highscore exactness is independently established by
its complete instruction, reference, and encoded-body comparisons.
