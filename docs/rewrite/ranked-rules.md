---
tags:
  - rewrite
  - contracts
---

# Ranked rules

A leaderboard run is a replay that verifies and satisfies these rules. The rules
version is the replay's `game_version`: a build with a rules bug is withdrawn
from the boards rather than frozen. The replay's `recorder` names the client and
platform that recorded it, so a faulty client can be withdrawn the same way. `crimson replay verify` reports `ranked`,
the `board` and every `unranked_reasons` entry; the leaderboard service applies
the same checks (`src/crimson/replay/ranked.py`).

## Boards and scores

| Board | Mode | Score |
| --- | --- | --- |
| `survival` | Survival | experience, higher wins |
| `quests` | Quests | final quest time, lower wins |
| `quests-hardcore` | Quests on hardcore | final quest time, lower wins |

Hardcore changes only quests, so Survival has one board. Each quest level ranks
on its own. Equal scores keep the earlier submission ahead. Accounts, uploads and
names are in [leaderboard identity](leaderboard-identity.md). Rush, Typ-o, the
Tutorial and co-op do not rank yet; the recovered core verifies one player in
Rush, Survival and Quests.

Only a finished run ranks: a Survival run that ended in death, or a completed
quest. A quit or a failed quest does not.

## The ranked profile

A ranked run starts from the same profile whatever the player's save holds, so
every setting that steers the RNG ([settings that steer the RNG](parity/environment-rng.md))
is pinned:

- one player, the documented fixes on (`preserve_bugs` off; see
  [original bugs](original-bugs.md));
- detail preset 5, violence on, friendly fire off;
- a save with every quest completed in both difficulties and no weapon used,
  so weapon and perk offers and the weapon-drop reroll draws match;
- no quest retries: every attempt plays as the first, at full difficulty;
- a fresh random seed for each attempt. Today the client draws it; the service
  will issue it.

The run itself keeps the replay contract: a fixed float32 1/60 s step, float32
inputs that must be finite, commands at the tick boundary, and no draws for
paused or menu frames ([replay run start](replay-run-start.md)).

## Controls and aim

Every tick uses human controls: relative, static, dual action pad or
point-click movement, with mouse, keyboard, joystick, relative mouse or dual
action pad aim. Computer movement and aim (an autopilot and an aimbot) and the
unknown aim scheme do not rank.

The original clamps the cursor to the screen, so the aim reaches only what the
player can see, and Telekinetic, Pyrokinetic and point-click movement act at
the aim point. Ranked runs fix the view at the native **1024x768**:

- a mouse aim point, and each new point-click target, lies inside the 1024x768
  view around the camera the previous tick left (centred on the player, plus
  the screen shake, clamped to the arena);
- a dual action pad aim reaches at most 138 units, the stick's full reach at
  the default `cv_padAimDistMul` of 96;
- relative mouse aim and keyboard or joystick aim only turn, so they carry no
  point to bound.

A smaller view, such as a wide window letterboxed to 1024x576, always lies
inside the 1024x768 one, so it ranks too.

## Playing a ranked run

The Play Game menu's **Ranked** box starts Survival and quest runs from the
ranked profile: it lists only those modes, keeps one player, draws a fresh
seed, caps the view at 1024x768 and uses the default pad reach. It is off while
player one uses computer controls. A ranked run plays on a detached copy of the
canonical save, exactly as verification replays it, so it does not change the
player's progress, and it leaves the regular quest retry count alone.
