---
tags:
  - rewrite
  - plan
---

# Watching replays

The plan for watching runs from the high score screen, in every client: your
own runs and the leaderboard's. Each client already records its runs and the
service already serves every ranked run's replay. Missing are a link from a
high score row to its replay, and playback inside the game.

We own every client, the service and the formats between them, so this changes
them where that is cleaner rather than working around them.

## Decisions

- **Watch** shows on every row whose replay the client can play.
- Watch needs the same simulation rules. A replay recorded under other rules,
  or in a format the client cannot read, says so instead of offering Watch. A
  replay from another build under the same rules plays, naming the build it
  came from.
- A perk pick shows as a popup: the offered perks, the chosen one marked.
  Playback does not stop for it.

## What each client can play

| Run | Python port | Web and native client |
| --- | --- | --- |
| One player, Survival, Rush, Quests | Yes | Yes |
| Co-op | Yes | No: the session simulates one player |
| Typ-o-Shooter, Tutorial | Yes | No: the verifier does not run them |
| Recorded by the other client | Yes | Yes, within the row above |

The web and native client records only the runs it can play back, which are
the runs it plays as sessions today (one player at 1024x768). Playback shows
the 1024x768 run scaled to the window. A run it cannot play shows "This run
needs the Python port" on its card.

## Replays

Every client saves a `.crd` for every run it can play back, numbered:
`replays/<n>-<mode>.crd`, where `n` is one more than the highest number in
`replays/`. A replay is listed only once its file is written whole.

- The Python port renames its `<mode>_<timestamp>.crd`.
- The web and native client stops writing its raw recording (`.rsi`) and
  writes `.crd`s with a general writer: the run's spec, its actual result
  (`incomplete` for an abandoned run, not `death`), its ticks, and recorder
  metadata the native client sets too. A ranked upload sends that same file.

The `.rsi` recordings a browser holds today are not migrated.

### The rules a replay was recorded under

Replay format 31 adds `rules`: an integer each client carries, raised whenever
a change makes earlier replays play differently. It is what Watch compares;
`game_version` stays the build, shown but not compared. Rules start at 1, and
a format 30 replay counts as rules 1: no change since format 30 makes them play
differently (the Survival board's top run, recorded with 0.12.2, verifies on
0.13.1). The service decodes both formats and keeps ranking by `game_version`
as the ranked rules say.

## A row names its replay

Both clients keep the original's 72-byte high score record.

- **A local record** holds its replay's number in the reserved word at `0x3C`,
  which the game's scores never read and the original's duplicate check leaves
  out. Zero is no replay: records saved before this change have none.
- **A leaderboard row** is not written into the local tables any more. Each
  client keeps the board's latest scores answer in memory for the session; every
  "Update scores" replaces it whole, so a run that was hidden, banned or deleted disappears at the
  next update and online rows never pile up. The table shows the local records
  and the kept answer's rows together, as the Python port already does; each
  answer row keeps its run id through the sort, and a local record that is on
  the board is marked online by matching it against the kept answer, so the
  mark follows the board too. The web and native client's "Update scores"
  (`game_scores_received`) changes from saving records into the tables to
  keeping the answer. Nothing online is stored: after a launch, internet rows
  show once "Update scores" has run, as in the original.
- The scores answer gains `run`, the run's id.

## Service

1. `run` in each score of the scores answer.
2. Replay format 31 decoded beside 30 (above).
3. The routes that take a run id (`/api/runs/<id>`, its timeline, its card and
   `/runs/<id>.crd`) refuse a banned account's run, as the boards do.
4. `/runs/<id>.crd` gains a short `cache-control`; hiding, bans and deletions
   still take effect within it. Tests for the route, a 404 kept apart from a
   failed download.

## Playability

| The replay | The card |
| --- | --- |
| Same rules | Watch (and the build, if another) |
| Other rules | "Recorded under other rules (0.12.2)" |
| Unreadable format | "Recorded by a version this one cannot read" |
| A run this client cannot simulate | "This run needs the Python port" |
| Gone from the leaderboard | "This run is no longer on the leaderboard" |
| Download failed | "Could not download this run" |

During playback, a tick the simulation refuses stops playback on that tick
with "This run stops playing here" and its tick. At the end, the full result is
compared with the recorded one; a difference shows "This run played
differently".

## Watching

The same in every client:

- **The high score screen** pins a row's card on click (hover still previews
  the others). The pinned card shows Watch or the reason.
- **Playback** runs the replay in the game's own view under a replay strip
  (time, length, speed). Esc returns to the scores with the row still pinned.
  Space pauses at once. `[` and `]` change speed. Right skips 5 s and Page Down
  30 s: a skip runs every tick, in bounded chunks per frame, with sound effects
  muted; music still changes as it would.
- **A perk pick** shows a popup beside the play area for a few seconds: the
  offered perks in the menu's order, the chosen one highlighted with its
  description, and the level. The simulation reports each pick as it applies
  it (the offers, the chosen index, the level and the tick); drawing the popup
  never regenerates choices or draws random numbers. A menu closed without a
  pick shows nothing.
- **The end** holds the last frame under the run's result: how it ended, its
  score and time, and whether it played as recorded. Esc returns.

Watching writes nothing: no save, statistics, play counts, scores or replays.
The writes are suppressed where they happen, not undone afterwards.

## Python port

1. `ReplayPlaybackMode` becomes a screen that uses the game's audio and console
   instead of its own, holds its last frame until Esc, and returns to the screen
   below it. `crimson replay play` runs the same screen in the app.
2. Picks become presentation events carrying their offers.
3. The replay saver numbers files and reports the path once written; the
   record's builder stores the number at `0x3C`.
4. Leaderboard rows keep their `run` from the merge to the card; Watch downloads
   `/runs/<id>.crd` on the client's worker into `replays/online/<id>.crd`.
5. The high score view pins rows and pushes the playback screen; the perk popup
   and the result panel are new widgets.

## Web and native client

1. **Replays.** The general `.crd` writer; numbered files; the number in the
   record when the run's record is saved.
2. **A `.crd` reader.** The vendored zstd 1.5.7 gains its decompressor and a
   canonical msgpack reader joins the writer, with bounds on the sizes they
   accept.
3. **A playback session.** `host/session.inc` gains a session kind for playback:
   config, input and commands from the replay; no settings carried back, no
   recording, no upload. It is set up before the recovered `game_state_set`
   runs, so the play counts it raises on entering gameplay and the status
   `quest_mode_update` saves on completion are suppressed at the source. A tick
   reports accepted, end of replay or refused, and only the first ends the
   session normally. A perk command never opens the interactive menu.
   Presentation random numbers stay legal while the session presents.
4. **Viewer controls.** A viewer pause stops ticking at once, unlike the run's
   own run-down pause; speed scales the time the session banks; a skip runs
   ticks in bounded chunks with sound effects muted.
5. **The high score screen** (`highscore_screen`), adapted: pinned rows, the
   card's Watch, leaderboard rows merged from the kept answer.
6. **The perk popup and result panel**, drawn with the original's panel, font
   and perk names after the game's frame, as the Ranked box is. The session
   records each pick's offers when it applies the pick.
7. **Leaderboard runs** (web): a host request has the page download
   `/runs/<id>.crd` into a buffer the module reads. Downloads are cached with a
   size limit, and a storage quota failure is reported, not ignored. The native
   client has no network yet and watches its own runs.

## Privacy

A Typ-o replay carries the local high score names its run read. The Python
port plays them locally; they are not uploaded, since Typ-o does not rank.
Leaderboard replays carry the name the player submitted, which a hidden name
does not cover; the identity page should say so.

## Checks

- Each client watches its own recorded runs and the other client's (fixtures),
  and the watched run reproduces the recorded result and intermediate state.
- The web and native client refuses co-op, Typ-o and Tutorial replays with the
  reason.
- Abandoned runs, quest completion and early exit, a refused tick, speeds and
  skips, audio on and off, watching twice in a row.
- Malformed and oversized files, an unknown format, other rules.
- No persistence write happens during playback (the file layer refuses one),
  not merely identical files afterwards.
- Hidden, banned and deleted leaderboard runs; a failed download; the browser's
  quota.

## Order

1. Service: `run` in scores, format 31, run-route visibility, the replay
   route's caching and tests.
2. Python: format 31 and `rules`, numbered replays and record links, pick
   events, the playback screen, then leaderboard Watch.
3. Web and native: the general writer and the reader, then the playback session
   with local Watch, then the screen, popup and leaderboard Watch.
