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
the `board` and every `unranked_reasons` entry from the run rules
(`src/crimson/replay/ranked.py`); the leaderboard service applies the same
checks to each upload, along with its signatures
([leaderboard identity](leaderboard-identity.md#uploads)).

## Boards and scores

| Board | Mode | Score |
| --- | --- | --- |
| `survival` | Survival | experience, higher wins |
| `quests` | Quests | final quest time, lower wins |
| `quests-hardcore` | Quests on hardcore | final quest time, lower wins |
| `survival-coop` | Survival, two players | experience, higher wins |
| `quests-coop` | Quests, two players | final quest time, lower wins |
| `quests-hardcore-coop` | Quests on hardcore, two players | final quest time, lower wins |

A co-op pair ranks on its own boards, scored as the one-player ones: two
players' scores do not compare with one player's, since XP is shared and two
players double the Survival spawn countdown.

A two-player run ranks only when its upload carries both players' signatures,
from two different keys, one for each seat; the service enforces this at
upload. `crimson replay verify` checks only the run rules, so it can report a
two-player replay as ranked that the service still refuses without the second
signature. How the two players sign one replay is in the
[network co-op spec](network-coop.md#53-run-setup-replays-ranked-co-op).

Hardcore applies only to quests, so Survival has one board for each team. (The original
leaks a saved Hardcore setting into Survival's milestone waves,
[original bug 38](original-bugs.md#38-quest-difficulty-leaks-into-survival-and-the-tutorial),
which the ranked rules fix; a ranked Survival run also records it off.) Each quest level ranks
on its own. Equal scores keep the earlier submission ahead. Accounts, uploads and
names are in [leaderboard identity](leaderboard-identity.md). Rush, Typ-o and the
Tutorial do not rank.

A [custom quest](../formats/quest-dsl.md) ranks one player only: its board, and
the clear that publishes it, are a single player's, so a two-player run of one
is unranked (`custom_quest_players`).

Only a finished run ranks: a Survival run that ended in death (every player's,
in co-op), or a completed quest. A quit or a failed quest does not.

Each board ranks human runs and bot runs apart, under these same rules. A run
is a bot run when its replay declares a pilot or a moderator puts it there; see
[bots and moderation](bots.md).

## When the verifier changes

A run stays on the boards while the current verifier still plays it to its
result. Before a release that changes the simulation or what a replay may do,
`npm run reverify` in `service/` replays every stored run through the new build,
as the service verifies an upload. A run that no longer verifies is retired with
the reason (`runs.retired`, set by a migration): it leaves the boards and the
game's scores, keeps its page, which says why, and its replay stays
downloadable.

## The ranked profile

A ranked run starts from the same profile whatever the player's save holds, so
every setting that steers the RNG ([settings that steer the RNG](parity/environment-rng.md))
is pinned:

- one player, or two on the co-op boards (`players` names any other count);
- the documented fixes on (`preserve_bugs` off; see
  [original bugs](original-bugs.md));
- detail preset 5, violence on, friendly fire off;
- a save with no weapon used and the progress the run's own place in the game
  gives, so weapon and perk offers and the weapon-drop reroll draws match:
    - Survival: every quest completed in both difficulties;
    - a quest: the save that has just unlocked it, with the quests before it
      completed, so it plays with the weapons and perks the campaign has handed
      out by then;
    - a hardcore quest: the whole normal campaign completed, and the hardcore
      quests before it;
- no quest retries: every attempt plays as the first, at full difficulty;
- a fresh random seed for each attempt, which the client draws. A seed the
  service issued would stop neither humans nor bots from shopping for one
  ([bots and moderation](bots.md)).

The run itself keeps the replay contract: a fixed float32 1/60 s step, float32
inputs that must be finite, commands at the tick boundary, and no draws for
paused or menu frames ([replay run start](replay-run-start.md)). Perk commands
follow the paused perk screen ([commands](../formats/replay.md#tick)).

## Controls and aim

Every tick of every player uses human controls: relative, static, dual action pad or
point-click movement, with mouse, keyboard, joystick, relative mouse or dual
action pad aim. Computer movement and aim (an autopilot and an aimbot) and the
unknown aim scheme do not rank.

The original clamps the cursor to the screen, so the aim reaches only what the
player can see, and Telekinetic, Pyrokinetic and point-click movement act at
the aim point. Ranked runs fix the view at the native **1024x768** and check
each player's aim against it:

- a mouse aim point, and each new point-click target, lies inside the 1024x768
  view around the camera the previous tick left (centred on the player and
  clamped to the arena, with a 96-unit margin that covers screen shake and a
  capped multi-tick frame of movement without giving offscreen reach). In
  co-op the camera follows the living players, centred between them, the view
  both players share; while nobody lives it stays where it was;
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
