---
icon: lucide/keyboard
tags:
  - mechanics
  - modes
  - typo
---

# Typ-o-Shooter

Shooting is replaced by typing. Every creature carries a name; type it and
press Enter to shoot it.

Unlocked once you clear quest 4.10, on either difficulty.

## Starting conditions

- Weapon: Shotgun, always.
- You stand still in the middle of the arena.
- Bonuses: off.
- Perks: off.
- Single-player only.

## Input

- Type to fill the line at the bottom of the screen. Backspace deletes the
  last letter.
- Enter checks the line against every living creature's name. On a match,
  you fire one 12-pellet blast at that creature. There's no cooldown or
  reload, so you shoot as fast as you type.
- Pellets kill anything in their way.
- The mouse doesn't aim: the trooper keeps facing the last creature it shot,
  even into the next run.

## Creatures

Every creature has 1 HP and does 100 contact damage, so one touch kills
you. Aliens move at 1.7; spiders move at 2.04, in jerky bursts. Their stats
never change during a run.

## Names

Names are built from 52 short words like "lamb", "gun", "head", "fox" and
"boom". "The" can only start a name. A run on the
[1.9.8 rules](../../rewrite/rules-1.9.8.md) builds names from 42 of these
words. Longer names come in as your kills grow:

| Kills | Name length |
| ---: | --- |
| Up to 20 | 1 word |
| 21–40 | 40% 2 words |
| 41–60 | 80% 2 words |
| 61–80 | 40% 3 words |
| 81–120 | 80% 3 words |
| Over 120 | 10% a high-score name, else 80% 4 words |

Names that miss their roll fall back to the shorter lengths. High-score
names come from your Typ-o high-score list ("quickbrownfox" if it has none).

Names are at most 15 letters; longer ones are rerolled up to 100 times. No
two living creatures share a name (the rewrite gives up after 200 tries).

!!! tip "Custom dictionary"

    The rewrite can load your own words from `typo_dictionary.txt` in the
    game directory. One word per line, up to 15 characters. Anything after
    `#` is a comment, and duplicates are dropped. Names are built from these
    words instead, with no word repeated within a name. Past 120 kills, the
    1-in-10 slot uses a single dictionary word.

## Spawning

A spider and an alien enter together, one off each side at the same height.
That height sweeps up and down the edges. A new pair comes every 3.5
seconds at first, 75 ms sooner each minute, down to 0.1 s at 45:20.

## Scoring

Score is kills, 1 point each, and ranks the high-score table. Hit % is
matched names out of Enter presses. The original keeps counting those
across runs in one session; the rewrite counts each run's own.

## Game over

The run ends once your death animation finishes.
