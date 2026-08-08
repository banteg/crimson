# `statistics_update_check_worker`

Native target: `crimsonland.exe` at `0x0042d8a0` (1364 bytes).

Work in progress: 77.38% normalized match, 22/361-instruction exact prefix,
373 candidate instructions, and 106/0/0 reference audit.

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
