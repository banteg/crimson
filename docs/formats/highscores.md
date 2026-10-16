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
is the sum of `(i + 3) * decoded_byte * 7`, modulo 2³², with each byte read as a
signed `char` (`0xFF` counts as `-1`). Readers skip invalid checksums and ignore
an incomplete trailing record.

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

The word at `0x3C` was reserved in the original, which never reads it and
leaves it out of its duplicate check. Every client stores the run's replay
number there, naming `replays/<n>-<mode>.crd`
([replay format](replay.md#where-replays-are-kept)). Zero is no replay, as in
every record written before replays were numbered; a number whose file is
missing is a replay that was not saved.

Normal quest files use `questhcM_N.hi`; hardcore uses `questM_N.hi`. That apparent
inversion is native behavior. Survival and Rush use `survival.hi` and `rush.hi`.
The original has no Typ-o name: `highscore_build_path` falls through to
`scores5\unknown.hi`, relative to the working directory rather than the game
folder, and Typ-o's high-score target names read that file too. The port keeps
`unknown.hi`, so an original install's Typ-o scores and names carry over; at
startup it merges tables an earlier port version saved as `typo.hi` into
`unknown.hi`. Two-player tables add `_2` before `.hi`; the port adds `_3` or
`_4` for its larger co-op tables.

Names are trimmed in the stored copy before encoding. Native trimming preserves
character zero even for an all-space name; the name-entry UI requires a
non-space character. A failed score write leaves name entry available for retry.

Implementation: `src/crimson/persistence/highscores.py`; the web and native clients set the replay
number in `crimson-core/host/session.inc` (`live_end`). The native behavior is in the
recovered sources under `decomp/1.9/crimsonland/highscore/` (`highscore_save_record.cpp`,
`highscore_load_table.cpp`, and the `highscore_compare_*` comparators).
