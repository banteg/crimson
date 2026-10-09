---
tags:
  - rewrite
  - contracts
---

# Replay viewer

How the browser and desktop game plays a replay back once
[watching replays](watch-replays.md) has started one: a transport bar with a
scrub bar, seeking anywhere and backwards, and a card for each perk pick, all in
the original's own art. The Python port keeps its own viewer for now.

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
a frame's share at a time (`WATCH_PASS_MS`), under the menus' panel and a bar of
the Options sliders' segments. On the way it:

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

- **The transport bar**, along the bottom: the HUD's top plate turned over, the
  original's buttons (back and forward 5 seconds, play and pause), the scrub
  bar of segments with the marks over it, the time and the speed. It slides
  away while the replay plays untouched and comes back with the cursor.
  Dragging on the scrub bar seeks as it goes; hovering shows the time and the
  mark under the cursor.
- **The pick card**, at the top right under where the level-up prompt swings
  in: the menus' panel with the level, the offered perks in the menu's order,
  the chosen one lit as the perk menu lights it, and its description.
- **The end panel**: how the run ended, its experience and kills, whether it
  played as recorded, Watch again and Back.
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
from the menu straight to the replay. A host can also ask for a tick to go to
(`game_watch_seek`) and one to pause at (`game_watch_stop_at`); the desktop
client takes them from `CRIMSON_WATCH`, `CRIMSON_WATCH_SEEK` and
`CRIMSON_WATCH_STOP` for unattended captures.
