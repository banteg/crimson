---
tags:
  - rewrite
  - contracts
---

# Bots and moderation

Each ranked board has two categories. **Human** runs are played live by a person through a stock client. **Bot**
runs are everything else: a program steering the inputs, tool-assisted runs (TAS) and any mix of the two. Both
categories follow the same [ranked rules](ranked-rules.md) and the same verification. The category only decides
which board a run is listed on.

The site shows both side by side: the home page has the top humans and the top bots, and every board page lists its
human runs and then its bot runs, each bot run under the bot its replay names.

A bot doesn't have to hide. A harness that declares itself goes straight to the bot board under its own name.
The human board relies on moderators, who see each run's input signals and can move a whole account or a single
run between categories.

## Decisions

- Two categories: `human` and `bot`. TAS is a bot run. Each board (Survival, each quest, each hardcore quest) ranks
  each category on its own, and an account can hold a best run in both.
- A bot declares itself with the replay's `pilot` field. The declaration is opt-in, and the board shows it as the
  operator's claim.
- Moderators mark **accounts** as bots. A single run can be moved either way when the account mark doesn't fit it.
- Signals are shown to moderators and never hide a run. A flagged run stays where it is until a moderator moves it.
- The seed stays the client's. The game is chaotic enough that a known seed doesn't help a human, and a bot can
  search its opening inputs instead of seeds, so a seed issued by the server would stop neither. A scripted bot
  test (2026-10-09) showed this: the Plasma Shotgun is the first weapon drop on 3.4% of seeds. Replaying a lucky
  seed with exactly the same inputs gives it every time, and with 1 px of aim noise 72% of the time. With human
  imprecision (20 px of aim noise, or starting 10 ticks late) it falls back to 2–6%. On one fixed seed, 69 of 1000
  slightly different openings gave it.
- There is no official bot harness yet. The Python port is open and scriptable, and a model can write a harness for
  it on its own.

## The category of a run

The service works a run's category out when it shows it, so a later moderator action applies to old runs too:

1. a moderator's choice for that run, if there is one;
2. otherwise `bot` when the replay declares a pilot or the account is marked as a bot;
3. otherwise `human`.

Ranks, the "best run" of a player and the in-game **Update scores** all count within a category. The game's high
score screen shows the human board.

## The pilot

A replay may carry `pilot`, the program that played it ([replay format](../formats/replay.md)):

| Field | Meaning |
| --- | --- |
| `name` | the bot's name, e.g. `Astra` |
| `model` | optional: the model or tool behind it, e.g. `gpt-5` or `TAS` |
| `url` | optional: an `https://` page about it, such as the harness's repository |

Verification ignores the pilot, the same as the recorder. The upload signs the whole payload, so only the key's
owner can add or change it. The Python port writes it when `CRIMSON_PILOT_NAME` is set, with
`CRIMSON_PILOT_MODEL` and `CRIMSON_PILOT_URL` as the optional fields. A harness that builds its own replays sets
the field itself. The bot board and the run page show the pilot next to the operator's account.

## The perk menu

The perk screen pauses the game, so a stock client can't play on while the menu is open or pick a perk without
opening it. The verifiers enforce this for every category:

- `perk_menu_open` is legal while a perk is pending and a player is alive (unchanged). The menu opens at the
  native mid-tick point, when it may open there.
- `perk_pick` is legal only as the first perk command of the tick right after the menu opened. One pick spends
  the open menu.
- A tick without a pick after the menu opened is the player pressing Cancel: the menu closes, and the next pick
  needs a new `perk_menu_open`.

A pick may be followed by a new `perk_menu_open` in the same tick: the player picked a perk and opened the menu again
for the next one.

## Signals

The verifier measures each run's inputs while it replays them, over the ticks where player one is alive:

| Signal | What it measures | Flag above | Astra (3 runs) | Humans (4 runs) |
| --- | --- | --- | --- | --- |
| `aim_on_creature` | share of ticks whose aim point is within 0.5 units of a living creature's centre | 0.02 | 0.15–0.20 | ≤0.0015 |
| `exact_moves` | share of dual-action-pad move ticks off the eight key directions whose stick is exactly unit length | 0.5 | 1.0 | 0 |
| `reversals_per_min` | move direction turns of more than 90° from one tick to the next, per minute | 30 | 257–337 | ≤1.7 |
| `aim_jump_p99` | the 99th percentile of the aim point's movement per tick, in units | 120 | 213–247 | ≤35 |
| `one_tick_fire` | fire presses held for exactly one tick | 50 | 327–915 | 0 |

The aim point is the world point the aim scheme reaches. That is the mouse point, the player's position plus
the pad's reach, or the cursor through the camera under relative mouse aim. Keyboard and joystick aim have none.
`overlapping_runs`, on the account, counts runs accepted sooner after the account's previous run than the run's
own game time. Uploads queued offline arrive together, so it's a hint for moderators, not a flag.

Every input check is easy to beat on purpose: noise, smoothing or human-like timing defeat each one. Signals catch
bots that don't try to hide, and they tell moderators where to look.

## Roles and moderation

Accounts have a role: none, `mod` or `admin`. Account 1 is the admin. The admin grants and removes the mod role.
Both roles can:

- see each run's signals and the flagged runs list (`/mod`);
- mark or unmark an account as a bot;
- set or clear a run's category.

Each action takes a note and goes to the moderation log, which moderators can read. Joining accounts keeps the bot
mark if either account had it and the stronger of their roles, so a join never moves a bot's runs to the human
boards or loses a moderator. The admin's account cannot be deleted from the site. The existing actions (hide a
run, hide a name, ban a key or an account) stay as they are.

The site's moderation API, for signed-in moderators only:

| Request | Does |
| --- | --- |
| `GET /api/mod/flags` | the human-category runs with a flagged signal, newest first |
| `GET /api/mod/log` | the latest moderation actions |
| `POST /api/mod/accounts/<id>` `{bot, note}` | marks or unmarks an account as a bot |
| `POST /api/mod/runs/<id>` `{category, note}` | sets a run's category (`human`, `bot`, or `null` to follow the account) |
| `POST /api/mod/roles/<id>` `{role, note}` | the admin only: sets an account's role (`mod` or none) |

Run pages show moderators the run's signals, how its category was decided and the controls to change it. Profiles
show them the account's mark and `overlapping_runs`.
