---
tags:
  - rewrite
  - contracts
---

# Replay viewer

How the browser and desktop game plays a replay back once
[watching replays](watch-replays.md) has started one: a scrub bar that seeks
anywhere, backwards too, and a box for each perk pick. While the replay plays,
the viewer keeps to plain dim bands of its own, so it stays clear of the game's
HUD; preparing and the end are the original's game over screen with the run's
score card. The Python port keeps its own viewer for now.

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
  batch by batch, and copies the terrain render target as the run starts and
  every 30 seconds (at most 32 copies, the spacing doubling past them);
- collects the **marks** the scrub bar shows: Survival's milestone waves (the
  spawn stage `survival_update` advances: alien rings, the red alien boss,
  spider swarms, fast aliens, stop-and-go spiders, the spider boss, splitters,
  plasma spiders and the second spider boss), Energizer drops, and every perk pick with the choices the
  menu offered;
- reaches the end and judges the run: played as recorded, played differently,
  or stopped at a tick the simulation refuses.

## Seeking

A seek to a tick restores the nearest keyframe before it, then plays forward,
undrawn, to it; a seek forward that no keyframe beats just plays on. A restore
also rebuilds the terrain: the nearest copy at or before the keyframe, then the
logged bakes after it through the original's own `fx_queue_render`, so blood
and corpses lie exactly where straight play left them. Ticks that are not drawn
still bake, so a skip leaves the terrain whole too.

`checks/game_seek.mjs` seeks across a fixture in a shuffled order and requires
the verifier's world at every tick; a native capture of a seek and of straight
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
  rank and day the site gives.
- **Keys**: Space pauses (or, at the end, plays again), period and comma step a
  tick while paused, `[` and `]` change the speed from 0.25x to 32x and `1`
  resets it, Left and Right go 5 seconds, Page Up and Page Down 30, Home and End
  to the start and the end, Escape returns to the scores.

A frame with no tick (paused, or between ticks at slow speeds) shows the last
drawn frame again (`host_frame_hold`) under the viewer, and ticks give the
cursor back to the viewer after they move it to the replay's aim.

## Links

A link to a run (`crimson.land/play/?watch=<run>`) names the run on the page's
cover and offers Watch; the game skips its intro, as a click would, and cuts
from the menu straight to the replay. The page gives the game the runner's
name (`game_watch_name`), and the board's rank and the day it took the run
(`game_watch`), for the score card. A host can also ask for a tick to go to
(`game_watch_seek`) and one to pause at (`game_watch_stop_at`); the desktop
client takes them from `CRIMSON_WATCH`, `CRIMSON_WATCH_CARD`,
`CRIMSON_WATCH_SEEK` and `CRIMSON_WATCH_STOP` for unattended captures.
