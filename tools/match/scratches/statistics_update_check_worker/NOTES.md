# `statistics_update_check_worker`

Native target: `crimsonland.exe` at `0x0042d8a0` (1364 bytes).

Work in progress: 69.95% normalized match, 21/361-instruction exact prefix,
371 candidate instructions, and 101/1/0 reference audit.

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
