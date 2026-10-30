---
tags:
  - rewrite
  - contracts
---

# Replay viewer

How the browser and desktop game plays a replay back once Watch on the high
score screen, or a link, has started one: a scrub bar that seeks anywhere,
backwards too, and a box for each perk pick. While the replay plays, the viewer
keeps to plain dim bands of its own, so it stays clear of the game's HUD;
preparing and the end are the original's game over screen with the run's score
card. The Python port has the same viewer, but prepares while the replay plays
([below](#the-python-port)). Playing a replay writes nothing: no save,
statistics or scores, and no replay of its own.

## Watch

A click on a high score row pins its card; the card offers Watch when the row's
replay plays, or says why not. A local record names its replay by number
([local high scores](../formats/highscores.md)); a leaderboard row by its run,
whose replay is downloaded when the row is pinned
([where replays are kept](../formats/replay.md#where-replays-are-kept)).

| The row's replay | The card |
| --- | --- |
| Plays, recorded by this build | Watch |
| Plays, recorded by another build under the same rules | Watch, with "Recorded with 0.14.2" |
| Recorded under other rules | "Recorded under other rules (0.12.2)" |
| A file or format this build cannot read | "This version cannot read its replay" |
| A local run whose replay was not saved | "Its replay was not saved" |
| A board run still downloading | "Downloading the run..." |
| A board run no longer on the board | "This run is no longer on the leaderboard" |
| A failed download | "Could not download this run" |
| Web and native: Typ-o, the Tutorial, or three or four players | "This run needs the Python port" |
| Web and native: a screen other than 1024x768 | "Watching needs the 1024x768 screen" |

A tick the simulation refuses stops the run there: the end screen says "This
run stops playing here" with the tick.

## What it can afford

Measured on 9-minute Survival runs (33,000 to 35,000 ticks):

| | |
| --- | --- |
| The verifier core, straight through | about 54,000 ticks/s (900x real time) |
| The game module with drawing off | about 36,000 ticks/s |
| A tick's state, as the core keeps it, zstd level 1 | about 55 KB, packed in about 1 ms |
| The browser game at 1x and 32x | 60 frames/s |
| Preparing the run (below), in Node / the browser | about 1.1 s / about 3 s |
| A seek anywhere, backwards too | 2 to 5 ms in Node; within a frame in the browser |

So the viewer prepares the whole run before it plays, keeps a keyframe every
2 seconds, and draws only the last tick of each frame at any speed.

## Preparing

Watch starts the run, then a preparing pass plays the whole recording undrawn,
a frame's share at a time (`WATCH_PASS_MS`), on the game over screen's panel
with the run's score card and a bar of the Options sliders' segments. On the
way it:

- keeps a **keyframe** every 120 ticks: the executable's per-run globals (the
  spans `game.py` resets at a run's start) and the session's own (host.cpp's
  statics, the run's settings, the first hit's music latch and the screen's
  transition), zstd-packed. Past 256 MB, every other keyframe goes and the
  spacing doubles;
- logs every **bake into the terrain**: `fx_queue_render`'s decals and corpses,
  batch by batch, zstd-packed 65,536 entries at a time (a long run bakes
  millions), and copies the terrain render target as the run starts and
  every 30 seconds, with spacing doubling at eight copies in either mode. At the
  default 2048×2048 physical size, classic costs at most 128 MiB; RTX's clean
  initial terrain plus seven complete material copies costs at most 800 MiB.
  RTX restores all material planes and their wetness epoch;
- collects the **marks** the scrub bar shows: Survival's milestone waves (the
  spawn stage `survival_update` advances: alien rings, the red alien boss,
  spider swarms, fast aliens, stop-and-go spiders, the spider boss, splitters,
  plasma spiders and the second spider boss), Energizer drops, and every perk pick with the choices the
  menu offered;
- reaches the end and judges the run: played as recorded, played differently,
  or stopped at a tick the simulation refuses.

For evaluations that play the same replay again and again, the desktop client
keeps a prepared run on disk (`CRIMSON_WATCH_CACHE=1`,
[`host/watch_cache.inc`](../../crimson-core/host/watch_cache.inc)): the
keyframes, bake logs, marks, tunes and judgement, with the terrain copies read
back from the GPU, in the game folder's `cache/prepared`, named by the client's
build, the replay and the render mode (RTX bakes the terrain its own way). The
next run of it skips the pass and plays from the first frame; the oldest files
go as new ones come. WebGPU reads a target back only by waiting on the GPU, so
the browser keeps none.

## Seeking

A seek to a tick restores the nearest keyframe before it, then plays forward,
undrawn, to it; a seek forward that no keyframe beats just plays on. A restore
also rebuilds the terrain: the nearest copy at or before the keyframe, then the
logged bakes after it through the original's own `fx_queue_render`, so blood
and corpses lie exactly where straight play left them. Ticks that are not drawn
still bake, so a skip leaves the terrain whole too.

Ticks nobody hears, the preparing pass's and a seek's, play no sound: the run
still picks its in-game tune as it did (the playlist latch and its random draw
are the run's), but no track starts and the music's volumes and fades come back
after them. A link stops the menu theme its skipped intro started. After a
seek, the music is the tune the run has there, from the tunes the preparing
pass noted it starting: scrubbing within the run never restarts it, Watch Again
fades the game over tune out, and before the first hit an in-game tune already
playing plays on.

`checks/game_seek.mjs` seeks across a fixture, then the service's co-op runs,
in a shuffled order and requires the verifier's world at every tick; a native capture of a seek and of straight
play to the same tick match pixel for pixel.

## The viewer

- **The scrub bar**, along the bottom on a dim band, which keeps it clear on
  any ground, snow too: the Options sliders' segments with the marks over them,
  Paused or the speed on its left (a click steps the speed) and the time on its
  right. It slides away while the replay plays untouched and comes back with the
  cursor. Dragging on it seeks as it goes; hovering shows the time and the mark
  under the cursor. A click on the world pauses or plays on.
- **The pick box**, at the top right under where the level-up prompt swings
  in: the level and the offered perks in the menu's order, the chosen one lit,
  on a dim box with the perk menu's blue along its top.
- **The end**, as the original ends a run: the game over screen's panel with
  The Reaper got you (Well done trooper! for a completed quest), whether it
  played as recorded where the original says a score is too low, the run's
  score card, and Watch Again and High scores.
- **The score card** is the high score screen's: the runner's name, where the
  score is from, the day, the score and its rank, the time, the weapon used
  most, frags and hits. Watch on the high score screen shows the row's own
  record; a link to a run builds it from the replay's result, under the name,
  rank and day the site gives (a co-op run's players as "A & B", as the
  game's boards name them).
- **Keys**: Space pauses (or, at the end, plays again), period and comma step a
  tick while paused, `[` and `]` change the speed from 0.25x to 32x and `1`
  resets it, Left and Right go 5 seconds, Page Up and Page Down 30, Home and End
  to the start and the end, Escape returns to the scores.

A frame with no tick (paused, or between ticks at slow speeds) shows the last
drawn frame again (`host_frame_hold`) under the viewer, and ticks give the
cursor back to the viewer after they move it to the replay's aim.

## Co-op runs

A co-op run's replay plays as the run did: both players' inputs each tick and
each perk pick by the player who asked for the menu, through the same
preparing pass, keyframes and seeks. The world is the original's for two
players: the camera on the midpoint of the living players (on the survivor
once one dies, where it was once both have), and both players' HUD. The pick
box and a pick's mark on the scrub bar name the picker ("Level 5 - Player 2").
Take over plays one player's live input, so a co-op run's bar says "One player
only" in its place.

`checks/game_watch.mjs` and `checks/game_seek.mjs` watch and seek the
service's co-op vectors (a Survival run and a custom quest's clear) to the
verifier's world, and `checks/game_coop_live.mjs` watches runs two games played
together, perk picks from both seats among them.

## Links

A link to a run (`crimson.land/play/?watch=<run>`) names the run on the page's
cover and offers Watch; the game skips its intro, as a click would, and cuts
from the menu straight to the replay. The page gives the game the runner's
name (`game_watch_name`), and the board's rank and the day it took the run
(`game_watch`), for the score card.

A link to a moment (`?watch=<run>&tick=<start>&stop=<end>`) addresses the run in
replay ticks (`1..ticks`), since Reflex Boost slows ticks and game-time seconds
cannot be converted by multiplying by 60: `tick=N` shows the world after `N`
recorded ticks have played (`game_watch_tick() == N`), and `stop=M` pauses once
playback has played `M` ticks (`game_watch_tick() == M`), clearing `stop` so the
recipient can resume or scrub the rest of the run. While watching a public run
in the browser, **Share from here** copies a link for the current tick (with an
optional `stop` tick), and **Full run** returns to tick 1 with `stop` cleared.
Out-of-range or malformed parameters and unavailable runs show a notice. The
host API exposes `game_watch_moment` (or `game_watch_seek` and
`game_watch_stop_at` unchecked), `game_watch_link_run` and `game_watch_run`;
the desktop client also takes `CRIMSON_WATCH`,
`CRIMSON_WATCH_CARD`, `CRIMSON_WATCH_SEEK`, `CRIMSON_WATCH_STOP`,
`CRIMSON_WATCH_MOMENTS` and `CRIMSON_WATCH_CACHE` for unattended captures.

## Practice takeover

In the native and web clients, **Take over** on the replay bar (or Enter) plays
on from the displayed alive tick at once, at 1x, aimed where the cursor is. A
fire button held from the takeover click fires only once let go. The branch
uses the player's controls and the recorded run's settings; pending and future
perks use the normal perk menu, and play carries on after a pick.

Escape pauses with Resume, Retry from the anchor and Watch the original;
Resume and Retry play on at once. Focus loss pauses. Death or quest completion
offers retry and return, without score or name entry. Return restores the
original anchor, paused, at its old viewer speed. Preparing, seeking, dead and
finished moments cannot be taken over.

Practice stays on Watch's detached save: it writes no progress, unlocks,
high scores, recordings or upload outbox entries. Attempts are unsaved in this
version. The original recording, keyframes and terrain log remain unchanged.
Retry rebuilds the original terrain through seek, then restores the exact
captured anchor, while retaining the human cursor. One extra render target
keeps the anchor frame including the animated HUD; retry and return copy it
back after rebuilding terrain. Leaving Watch releases it.

`checks/game_practice.mjs` compares alternate live inputs after a restored
anchor with initialization plus the recorded prefix and those same inputs.
It covers Survival, Rush and Quests, early/keyframe/late anchors, pending perk
choices, the held takeover click, focus loss, retry, return and persistence.
Native frame captures additionally check the rendered terrain and HUD on
retry and return. The Python viewer's takeover is a follow-up.

## The Python port

The Python simulation plays about 4,000 ticks/s early in a run and about 640
late in a 9-minute Survival run, so preparing that run first would take about
a minute. The port plays the replay at once and prepares in a process of its
own (`ReplayPreparation`), which sends what it finds every half second of the
run:

- a **keyframe** every 30 ticks: the driver's session and its run-down,
  pickled and zstd-packed (about 30 KB, 3 ms to pack, 2 ms to restore), with
  the render-only clocks and where the camera last followed the players. A
  seek plays at most 29 ticks after its keyframe, a few hundredths of a
  second. Past 256 MB, every other keyframe goes;
- the **bakes** into the terrain, zstd-packed a span at a time. The process
  draws nothing, so the viewer keeps a terrain of its own that bakes the log
  as it comes in and copies it as the run starts and every 30 seconds after
  (`TerrainHistory`), for seeks to rebuild from;
- the scrub bar's **marks**, the **perk picks** with the menu's offers, and the
  **tunes** the run starts: the in-game tune's draw from the replay's own sound
  randomness, the quest's completion tune, and a death's game over tune.

A seek goes as far as the pass has played (or playback itself, if it is
ahead); the bar draws the segments past that fainter. A 9-minute Survival run
is prepared in about a minute; a quest in a few seconds. At high speeds,
playback runs as fast as the simulation does: a frame plays at most a
thirtieth of a second of ticks.

The music is the viewer's: the run's own music calls do not play, and after
every frame and seek the viewer plays the tune the run has there. The score
card is the high score row's; `crimson replay play` builds it from the
replay's result, named after its pilot and dated by its file, and its end
screen's second button closes the window.
