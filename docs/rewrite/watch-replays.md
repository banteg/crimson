---
tags:
  - rewrite
  - plan
---

# Watching replays

The plan for watching any run from the high score screen, in every client:
your own runs and the leaderboard's. Each client already records every run and
the service already serves every ranked run's replay; what is missing is a link
from a high score row to its replay, and a way to play it inside the game.

We own every client, the service and the formats between them, so this changes
them where that is cleaner rather than working around them.

## Decisions

- **Watch** shows on every row whose replay the client can play: local runs it
  recorded and leaderboard runs.
- A replay recorded by another `game_version` plays with a warning. A replay
  the client knows it cannot play, an older replay format or a version before
  the current rules epoch, shows why instead of Watch.
- A perk pick shows as a popup: the perks that were offered, with the chosen
  one marked. Playback does not stop for it.

## One replay format, one naming

Every client saves a `.crd` (format 30) for every run, named by its seed:
`replays/<mode>-<seed>.crd`, with `-1`, `-2`... when a name is taken.

- The Python port renames its `<mode>_<timestamp>.crd`.
- The web and native client stops writing its raw recording (`.rsi`, the
  verifier's transport) and writes the same `.crd` the ranked upload sends: the
  payload writer in `host/ranked.inc` becomes the writer for every run, and a
  ranked run uploads that file. The transport stays a service-side encoding.

The `.rsi` files a browser holds today become unreadable; the clients' own
earlier replays are not migrated.

## A row names its run

Both clients keep the original's 72-byte high score record. Its reserved word at
`0x3C`, which the game's own scores never read and the duplicate check leaves out,
holds the run's seed:

- A local record gets it when the client saves the record for a run.
- A leaderboard record gets it from the scores answer.

Watch finds the replay by seed: a local row opens `replays/<mode>-<seed>*.crd`
whose result matches the record (mode, quest, score, time and kills); a
leaderboard row looks its seed up in the board's scores answer and downloads
that run. A record saved before this change has no seed and no Watch.

## Service

1. `runs.seed`: a migration adds the column; a script fills it for the stored
   runs from their replays, and an upload sets it.
2. The scores answer gains `run` (the run id) and `seed` for each score.
   Clients that do not know them ignore them.
3. `GET /runs/<id>.crd` already serves a visible run's replay. It gains a short
   `cache-control` (the bytes never change; hiding, bans and deletions still
   have to take effect) and the tests it lacks.

Separately, the routes that take a run id serve a banned account's run; only the
boards filter bans. That is a fix of its own.

## Playability

A client decides before offering Watch:

| The replay | Watch |
| --- | --- |
| Decodes, same `game_version` | Plays |
| Decodes, another `game_version` at or after the client's rules epoch | Plays, with "recorded with 0.12.2, it may play differently" |
| Another replay format, or a `game_version` before the rules epoch | "Recorded with 0.11, which this version cannot play" |
| Download failed or the run is gone | "This run is no longer on the leaderboard" |

The rules epoch is a version each client carries, raised when a change makes
earlier replays play differently. A replay that still plays differently, which
the client finds when its result at the end differs from the recorded one, ends
on "This run played differently in this version".

## Watching

The same in every client:

- **The high score screen** pins a row's card on click (hover still previews
  the others). The pinned card shows Watch, the warning or the reason.
- **Playback** runs the replay in the game's own view, with a replay strip
  (time, length, speed). Esc returns to the scores with the row still pinned;
  Space pauses; `[` and `]` change speed; Right skips 5 s and Page Down 30 s,
  muted while skipping.
- **A perk pick** shows a popup beside the play area for a few seconds: the
  offered perks in the menu's order, the chosen one highlighted with its
  description, and the level it came with. A menu closed without a pick shows
  nothing.
- **The end** holds the last frame under the run's result: how it ended, its
  score and time, and whether it played as recorded. Esc returns.

Watching never changes the player's save, scores, statistics or replays.

## Python port

1. `ReplayPlaybackMode` becomes a screen: it takes the game's audio and console
   instead of making its own, returns to the screen below it at the end, and
   `crimson replay play` runs the same screen in the app.
2. The replay saver names files by seed and reports the path; the high score
   record reads and writes its seed at `0x3C`, set when a run's record is built
   and when a leaderboard row is made.
3. The leaderboard client keeps `run` and `seed` from the scores answer and
   downloads `/runs/<id>.crd` on its worker into `replays/online/<id>.crd`.
4. The high score view pins rows and pushes the playback screen; the perk popup
   and the result panel are new widgets.

## Web and native client

1. **Replays.** Every run saves its `.crd`; a ranked run's upload is that file
   (above).
2. **A `.crd` reader in the module.** The vendored zstd 1.5.7 gains its
   decompressor beside the compressor, and a canonical msgpack reader joins the
   writer, so the module reads its own replays, the Python port's and the
   leaderboard's, native included.
3. **A session plays from a source.** `host/session.inc` runs a session from the
   player (as now) or from a replay: config, input and commands from the
   replay; no settings carried into the save, no saved replay, no ranked
   upload, no play counts, no high score entry and no results screen. Quest
   completion saves the player's status inside the tick, so the session keeps
   the player's status and restores it. A replay session ends on the high score
   screen.
4. **Viewer controls.** Pause is the run-down pause the client already has;
   speed scales the time the session banks; a skip runs ticks muted.
5. **High score screen.** The original's screen (`highscore_screen`), adapted:
   pinned rows, the card's Watch, and the seed written where the record is
   saved and where a leaderboard row arrives.
6. **The perk popup and result panel**, drawn with the original's panel, font
   and perk names after the game's frame, as the Ranked box is.
7. **Leaderboard runs** (web): a new host request has the page download
   `/runs/<id>.crd` into a buffer the module reads. The native client has no
   network yet, so it watches its own runs.
8. **Checks.** A new check records a run, watches it from the high score screen
   and requires the watched run to end in the recorded result, with the save,
   the scores and `replays/` unchanged.

## Order

1. Service: `runs.seed`, `run` and `seed` in scores, the replay route's caching
   and tests.
2. Python: the playback screen, seed naming and links, then leaderboard Watch.
3. Web and native: `.crd` replays and the reader, then the replay session with
   local Watch, then the screen, popup and leaderboard Watch.
