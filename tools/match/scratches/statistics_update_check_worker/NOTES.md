# `statistics_update_check_worker`

Native target: `crimsonland.exe` at `0x0042d8a0` (1364 bytes).

Work in progress: 76.84% normalized match, 21/361-instruction exact prefix,
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
`FUN_00462ba0`. Live Binary Ninja shows the sole call from this worker, the
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

Moving the MIME array beside the request-path slot and permuting the three
version-output declarations were byte-identical. An explicit shared
host/request-path buffer instead regressed from 69.95% to 66.04%, removed the
21-instruction exact prefix, and introduced a reference mismatch. The
remaining stack-slot order, literal lowering, tail merging, and scan-output
allocation are therefore compiler residuals. The scratch is classified
`semantic-complete` with a `compiler` residual.

`request-path-initializer-mutations.json` evaluated three direct, aggregate,
and staged request-path initializers. Every alternative regressed by at least
57.76 fuzzy-weighted bytes and lost native-prefix or reference agreement. The
existing initializer is retained.
