---
tags:
  - formats
  - rewrite
---

# Local high scores

Local score files under `scores5/` contain a sequence of independently encoded
records. There is no file header. Each record has a `0x48`-byte payload followed
by a little-endian `u32` checksum, for a `0x4c`-byte wire record.

For byte index `i`, encoding adds `(i * 5 + 1) * i + 6`, modulo 256. The checksum
is the sum of `(i + 3) * decoded_byte * 7`, modulo 2³². Readers skip invalid
checksums and ignore an incomplete trailing record.

The name occupies the first `0x20` bytes. Time at offset `0x20` is a signed
32-bit millisecond value: quest bonuses can make it negative. The score field
at `0x24` is also compared as a signed native integer. Survival/Typ-o rank by
score descending; Rush ranks by time descending; quests rank by time ascending
with zero last. Equal scores keep their existing order in the port.

Date bytes at `0x40`–`0x43` hold day, native `dateWeek`, month, and year minus
2000. Month/week/day filters use the local calendar and run before the 100-row
display limit. The week filter compares the stored native week and year, not
Python's ISO week number. Saving a qualifying score retains historical records
outside the selected table. Port writes atomically replace the file.

Normal quest files use `questhcM_N.hi`; hardcore uses `questM_N.hi`. That apparent
inversion is native behavior. The port adds `_2`, `_3`, or `_4` before `.hi` for
separate local co-op tables. Other modes use `survival.hi`, `rush.hi`, and
`typo.hi`.

Names are trimmed in the stored copy before encoding. Native trimming preserves
character zero even for an all-space name; the name-entry UI requires a
non-space character. A failed score write leaves name entry available for retry.

Implementations: `src/crimson/persistence/highscores.py` and
`crimson-zig/src/persistence/highscores.zig`. Native evidence is maintained in
the `highscore_save_record`, `highscore_load_table`, and `highscore_compare_*`
matching sources under `tools/match/scratches/`.
