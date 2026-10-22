---
tags:
  - formats
  - rewrite
---

# Local high scores

The port keeps every local score in one file, `scores.jsonl` in the data
folder, which the Python game and the native and web clients share. The
original's per-table `scores5/*.hi` files import into it.

## scores.jsonl

One JSON object per line, appended when a run is saved:

```json
{"v":1,"name":"banteg","game_mode_id":1,"run_elapsed_ms":754321,"score_xp":98765,"most_used_weapon_id":3,"shots_fired":900,"shots_hit":600,"creature_kill_count":410,"uni_num":12345,"date":"2026-10-22","replay_number":17,"run":"<sha256>","rules":2,"game_version":"0.21.0"}
```

`v` is the record version. A field at its default is left out: no quest, not
hardcore, one player, the default list, zero counters, no replay. A reader
skips a line it cannot decode, such as one a crash left half written, and a
writer starts a new line after it.

The v1 readers use the same strict contract. `v` is required and must be the
integer `1`; unknown or duplicate fields reject the line. Integer fields take
integer JSON tokens (not `1.0`, strings or booleans), with the signed/unsigned
32-bit bounds below. Modes must be known, weapons are `0..53`, and player count
is `1..4`. A quest level is null or `{major: 1..5, minor: 1..10}`, and only quest
scores may carry one. Booleans must be JSON booleans. Dates are null or valid
`YYYY-MM-DD` dates in `2000..2255`, the original's representable calendar.

Names and named lists are at most 31 Latin-1 characters; build strings also
use Latin-1. NUL is rejected, and strings use valid UTF-8 on disk. A run id is
empty or 64 lowercase hexadecimal digits; rules are null or an unsigned
32-bit integer. `received: true` is never a local record. Missing fields take
their documented defaults. `tests/persistence/score_contract.json` exercises
both production decoders, including malformed and boundary values.

| Field | Holds |
| --- | --- |
| `name` | The name typed at the results screen, trailing spaces trimmed down to the first character, as `highscore_save_record` does. |
| `game_mode_id`, `quest_level`, `hardcore`, `player_count`, `score_list` | The table the record belongs to. |
| `run_elapsed_ms` | Game time in ms, signed; a quest stores its final time, which bonuses can make negative. |
| `score_xp` | XP, or kills in Typ-o. |
| `most_used_weapon_id`, `shots_fired`, `shots_hit`, `creature_kill_count` | The score card's stats. |
| `uni_num` | The random tag `highscore_record_init` draws. |
| `date` | The local date the record was saved. |
| `replay_number` | The run's replay, `replays/<n>-<mode>.crd` ([replay format](replay.md#where-replays-are-kept)); none for a record imported from before replays were numbered. A number whose file is missing is a replay that was not saved. |
| `run` | The run's leaderboard id, the SHA-256 of its replay payload. |
| `rules`, `game_version` | The replay's rules and build. |
| `import_id` | Empty for a new run; for an imported row, the source digest followed by `:` and its decimal byte offset. |

A table is a mode, its player count and the selected named list; each quest
has a table per difficulty. Survival, Rush and Typ-o keep hardcore runs in
their one table, as the original does. Typ-o's table also gives Typ-o its
high-score target names.

Survival and Typ-o rank by score descending, Rush by time descending, quests
by time ascending with zero last; both fields compare as signed 32-bit values,
as the native comparators do. Equal scores keep their saved order. The
month, week and day filters use the local calendar, with the native
`dateWeek` week rather than an ISO week, and run before the 100-row display
limit. Saving a qualifying score keeps every record outside the shown table.

Records received from the leaderboard are never saved. While **Show internet
scores** is on, a local record the board holds turns green: it matches by
`run`, or, for an imported record without one, by name, time and XP.

Writers hold the score file's exclusive lock while repairing its tail and
completing partial writes, then flush it before acknowledging success. Python
uses `flock` on macOS/Linux and a byte-range lock on Windows; the desktop host
takes the same `flock`. The browser already owns its directory with a Web Lock
and persists it through its existing IndexedDB synchronization. A failed append
rolls back its bytes while holding the lock, so retrying a save does not keep a
partially completed batch.

## Import from scores5

At startup each `scores5/*.hi*` file's records are appended to
`scores.jsonl`, and the file moves to `scores5/imported/` (with `.1`, `.2`…
when that name is taken). A table an older client writes later imports on the
next start. The file name gives the player count and the named list; the
record gives the mode, quest and difficulty. Records the original received
from the internet stay out.

An imported row's source digest is SHA-256 of the original file name in UTF-8,
a NUL byte, and the complete source file bytes. Its offset counts from the
start of that file, including invalid and internet records. Readers keep the
first valid row for each nonempty `import_id`, so an interrupted or concurrent
import can append again without duplicating visible scores. Identical rows at
different offsets remain distinct. Failed writes leave the source in place;
archives retain invalid rows for recovery. Invalid enum/calendar fields are
skipped, and non-quest rows discard the original's stale quest-stage bytes.

### The original's format

Each file is a sequence of independently encoded records with no header: a
`0x48`-byte payload followed by a little-endian `u32` checksum.

For byte index `i`, encoding adds `(i * 5 + 1) * i + 6`, modulo 256. The
checksum is the sum of `(i + 3) * decoded_byte * 7`, modulo 2³², with each
byte read as a signed `char` (`0xFF` counts as `-1`). Readers skip invalid
checksums and ignore an incomplete trailing record.

| Offset | Field |
| --- | --- |
| `0x00` | Name, `0x20` bytes, NUL-terminated Latin-1. |
| `0x20` | Time, signed ms. |
| `0x24` | Score. |
| `0x28`–`0x2B` | Mode, quest major and minor, most-used weapon. |
| `0x2C`–`0x38` | Shots fired, shots hit, kills, random tag. |
| `0x3C` | Reserved: never read, left out of the duplicate check. The port stored the replay number here. |
| `0x40`–`0x43` | Day, native `dateWeek`, month, year minus 2000. |
| `0x44` | Flags: bit 0 received from the internet, bit 1 of local origin. |
| `0x45` | `0x75` for a hardcore quest. |
| `0x46`–`0x47` | `0x7C 0xFF`. |

Normal quest files use `questhcM_N.hi`; hardcore uses `questM_N.hi`, an
apparent inversion that is native behavior. Survival and Rush use
`survival.hi` and `rush.hi`. The original has no Typ-o name:
`highscore_build_path` falls through to `scores5\unknown.hi`, relative to the
working directory rather than the game folder. An earlier port saved Typ-o's
table as `typo.hi`. Two-player tables add `_2` before `.hi`, and the port
added `_3` and `_4`; a named list appends its name after `.hi`.

Implementation: `src/crimson/persistence/highscores.py` and
`src/crimson/persistence/scores5.py`; the web and native clients' are in
`crimson-core/host/scores.inc`, which writes the same lines. The native behavior is in the recovered
sources under `decomp/1.9/crimsonland/highscore/` (`highscore_save_record.cpp`,
`highscore_load_table.cpp`, and the `highscore_compare_*` comparators).
