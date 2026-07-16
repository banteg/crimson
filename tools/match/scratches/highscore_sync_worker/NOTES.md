# `highscore_sync_worker`

Native target: `crimsonland.exe` at `0x0042d0e0` (1970 bytes).

Work in progress: 60.69% normalized match, 19/519-instruction exact prefix,
519 candidate instructions, and 102/0/0 reference audit. The candidate also
reproduces the native `0x160`-byte frame.

Live Binary Ninja evidence recovers the complete upload/download worker:

- it snapshots and later restores the active `0x48`-byte high-score record,
  drives `online_sync_status`, reloads the table around synchronization, and
  preserves the native 20 ms batch / 300 ms interactive delays;
- it builds the `42 48 f3 85` binary request header, selected-name/full-version
  gate, quest and mode bytes, and appends eligible packed `0x40`-byte records;
- it posts the native octet-stream header to
  `scores.crimsonland.com/scoring_v2_7.php` using the 10-entry MIME list,
  guest credentials, WinINet flags, and context `0x1289`;
- it reads in `0x400`-byte chunks with the native `0x8000` overflow guard and
  reports both Win32 and WinINet response errors on failure;
- it accepts response magic `0x15`, adds the two count bytes, validates exactly
  `count * 0x44` payload bytes, marks each received record active, stamps its
  hardcore marker, and saves it with the preserved native tail sentinels;
- invalid magic logs response diagnostics but still follows the native success
  path, whereas a read error or invalid record length follows failure cleanup;
- every request, connection, and session handle is closed after deleting the
  response buffer, and all terminal console/status transitions are present.

The remaining mismatch is compiler shape rather than missing behavior. The
native frame places the reused 64-byte host/path slot below the MIME array,
lowers both strings into individual stores, field-anchors the submit iterator,
keeps `InternetReadFile` results in `EAX`, and tail-merges several failure
messages. MSVC gives the typed candidate the opposite array-slot order, literal
block copies, a base-anchored record iterator, and different scalar stack-slot
reuse. Natural initializer, scoped-buffer, pointer-loop, read-loop, branch, and
declaration-order variants were tested; the retained source has the exact body
instruction count and best honest score without byte-spelled literals,
volatility, padding, fake references, or artificial register constraints.
