---
tags:
  - mechanics
  - systems
  - scores
---

# High scores and leaderboards

Every mode but the Tutorial keeps local high-score tables. Survival and the
quests also rank online at [crimson.land](https://crimson.land).

## Local tables

Open them from the main menu: **Statistics → High scores**, or **High
scores** on any results screen.

| Mode | Score | Order |
| --- | --- | --- |
| Survival | XP | highest first |
| Rush | time survived | longest first |
| Quests | [final time](../modes/quests.md#scoring) | fastest first |
| Typ-o-Shooter | kills | most first |

The table lists rank, score and name, up to 100 rows. Rush and quest times
show in whole seconds but rank to the millisecond.

Each quest has its own table on each difficulty; once you've beaten quest
4.10, tick **Hardcore** on the table to see hardcore times. Survival, Rush
and Typ-o have one table each. One- and two-player runs keep separate
tables (the rewrite adds 3- and 4-player ones); Typ-o is one-player only.

Runs on the [1.9.8 rules](../../rewrite/rules-1.9.8.md) keep tables of their
own. While **1.9.8** is ticked in the Play Game menu, High scores shows them,
with 1.9.8 in its title.

**Show scores** filters by date: best of all time, of this month, this week
or today. The filter applies before the 100-row cut.

**Selected score list** lets you add named lists. While one is selected,
your runs save to that list's own tables, apart from the default list.

## What a record holds

- Name, up to 20 characters.
- Time: game time, which stops while the game is paused. A quest stores its
  final time here.
- XP (in Typ-o, kills).
- Kills, shots fired and shots hit. The score card shows hit %.
- Most-used weapon: the gun player 1 held longest.
- The date, for the filters.

In co-op, kills and shots count the whole team, XP is the shared pool, and
the most-used weapon is player 1's.

## When a run is saved

- **Survival, Rush, Typ-o**: when you die. If the run makes the top 100 of
  the table on screen, you type a name and it's saved. If not, the game says
  *Score too low for top100.*
- **Quests**: only a completed quest. A failed quest shows where it would
  have ranked but is never saved.
- **Tutorial**: never.

!!! bug "Original bug"
    In the original executable, *Score too low* never shows: every run gets
    a name prompt and is saved. A table lists at most 99 runs, and each new
    run pushes out the weakest one shown, even when it scores lower itself,
    so the newest run is always listed. The rewrite keeps a true top 100.

## Hardcore and Survival

Hardcore is a quest setting (see [Quests](../modes/quests.md#hardcore)).
Survival, Rush and Typ-o have one table each and always play at normal
strength.

!!! bug "Original bug"
    In the original executable, the **Hardcore** box on the quest list is a
    saved setting that's only cleared while quest 4.10 is unbeaten, so a box
    left ticked leaks into Survival and the Tutorial. Their scripted
    creatures, including Survival's
    [milestone waves](../modes/survival.md#milestone-waves), come out
    [hardcore](../modes/quests.md#hardcore) (with the same
    [limit on formations](../modes/quests.md#formations)), and the run lands
    in the normal Survival table. Quitting a retried quest from the pause
    menu likewise carries its [retry easing](../modes/quests.md#retries)
    into them. The rewrite applies both only to quests; see [original bug 38](../../rewrite/original-bugs.md#38-quest-difficulty-leaks-into-survival-and-the-tutorial).

## Ranked play

The leaderboard at [crimson.land](https://crimson.land) has one board for
Survival and one per quest on each difficulty, and each comes once for each
build's rules: runs on the [1.9.8 rules](../../rewrite/rules-1.9.8.md#ranking)
rank on 1.9.8's boards. The server replays every run before it counts, and
keeps each account's best run per board. Bot runs and co-op pairs rank on
their own boards; see [Ranked rules](../../rewrite/ranked-rules.md#boards-and-scores).

Tick **Ranked** in the Play Game menu to play a run that can rank. A ranked
run plays the same setup for everyone:

- one player, with the rewrite's [bug fixes](classic-quirks.md) on;
- detail 5, violence on, friendly fire off;
- Survival on a save with every quest beaten on both difficulties;
- a quest on the save that has just unlocked it (a hardcore quest: the whole
  normal campaign, plus the hardcore quests before it);
- no weapon history, and no retry easing: every attempt is a first try;
- a fresh random seed for every attempt;
- your view capped at 1024×768, and the default pad aim reach.

Only a finished run ranks: a Survival run that ends in death, or a completed
quest. Rush, Typ-o, the Tutorial and local co-op don't rank. Online co-op
ranks without the box: every run two players start from an invite link at
[crimson.land/play](https://crimson.land/play/) is a ranked attempt for the
pair. Tick **1.9.8** as well for a ranked run on the 1.9.8 rules. Computer
controls never rank; the Ranked box is off while player 1 uses them.

A ranked run plays on a copy of the save, so it changes neither your
progress nor your quest retry count. It uploads once its results screen
closes; a run played offline uploads later. Equal scores keep the earlier
upload ahead.

On the High scores screen, **Show internet scores** mixes the board's runs
into a one-player Survival or quest table, and **Update scores** sends your
waiting runs and fetches the board.

The full rules are in [Ranked rules](../../rewrite/ranked-rules.md).

## Settings that change a run

None of these change a rule. Detail and violence still change how a run
plays out: their effects draw from the same random numbers as spawns and
drops, so the same seed goes differently.

- **Detail** (1–5): 1 and 2 drop shadows and flame glow, and 1 also drops
  smoke. Hit sparks and explosions also scale with detail.
- **Violence** off: no blood or corpses on the ground, white hit flashes,
  and Bloody Mess is called Quick Learner (same +30% XP).
- **Friendly fire** (`cv_friendlyFire`, see
  [console](secrets.md#console)): your shots hurt your co-op partner.

Ranked runs pin all three. Replays record them, so any run still verifies.
See [settings that steer the RNG](../../rewrite/parity/environment-rng.md).
