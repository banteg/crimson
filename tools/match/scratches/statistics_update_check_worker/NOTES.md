# `statistics_update_check_worker`

Native target: `crimsonland.exe` at `0x0042d8a0` (1364 bytes).

Work in progress: 69.95% normalized match, 21/361-instruction exact prefix,
371 candidate instructions, and 102/0/0 reference audit.

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

The remaining mismatch is code-generation shape rather than missing behavior.
The native frame places the reused 64-byte host/path slot below the MIME array
and lowers the 15-byte path initializer into individual stores; MSVC gives the
typed candidate the opposite array-slot order and four literal loads. It also
tail-merges the four native WinINet failure messages, caches
`InternetReadFile` in a register, and orders the three scan outputs differently.
Natural scope, initializer, loop, failure-label, and MSVC 6.6 variants were
tested; the retained source has the best aligned reference audit and avoids
padding, byte-by-byte source spelling, volatility, or artificial register
constraints.

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
reference-clean at `102/0/0`.

Moving the MIME array beside the request-path slot and permuting the three
version-output declarations were byte-identical. An explicit shared
host/request-path buffer instead regressed from 69.95% to 66.04%, removed the
21-instruction exact prefix, and introduced a reference mismatch. The
remaining stack-slot order, literal lowering, tail merging, and scan-output
allocation are therefore compiler residuals. The scratch is classified
`semantic-complete` with a `compiler` residual.
