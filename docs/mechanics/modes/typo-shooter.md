---
tags:
  - mechanics
  - modes
  - typo
---

# Typ-o-Shooter

Shooting is replaced by typing. Creatures are labeled with names, and
typing a name followed by Enter fires at the matching creature.

## Starting conditions

- Weapon: typing rifle (internal, not selectable).
- Bonuses: disabled. Weapon Power Up and Reflex Boost timers are cleared
  every frame.
- Perks: disabled.
- Single-player only.

## Input

- Type characters to build a buffer, displayed in a panel at the bottom
  of the screen.
- Press Enter to match the buffer against living creature names. On a
  match, the player fires at that creature.
- Backspace deletes the last character.
- Mouse still controls the aiming direction.

## Creature names

Names are randomly generated from a pool of 52 word parts (e.g. "lamb",
"gun", "head", "fox", "boom"). Complexity scales with the player's
score:

| Score | Name length |
| ---: | --- |
| 0–20 | 1 part |
| 21–40 | 1–2 parts |
| 41–80 | 1–3 parts |
| 81+ | 1–4 parts |

Higher part counts become more probable as score increases. Names must
be unique among living creatures (up to 200 reroll attempts). Maximum
length is 16 characters.

!!! tip "Custom dictionary"

    The rewrite supports loading a custom word list from
    `typo_dictionary.txt` placed in the game directory. One word per
    line, max 15 characters each. Lines starting with `#` are comments.
    When present, names are built by concatenating words from this file
    instead of the built-in parts.

## Spawning

Spawn cooldown decreases by `frame_dt × player_count` each frame. When
it crosses zero, a symmetric pair spawns from opposite edges:

- **Right edge**: Spider.
- **Left edge**: Alien.

Cooldown resets to:

`3500 − elapsed_ms / 800` (milliseconds, minimum 100)

Creatures are tinted based on elapsed time, shifting through color over
the course of a run.

## Player state

The typing rifle overrides normal weapon behavior every frame: shot
cooldown is zeroed, spread is reset, ammo is kept full, and reload is
inactive.

## Scoring

Ranked by elapsed time. The record includes shots fired (Enter presses)
and shots hit (successful name matches).

## Game over

The run ends when the player dies and the death timer completes.
