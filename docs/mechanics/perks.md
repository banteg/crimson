---
tags:
  - mechanics
  - systems
  - perks
---

# Perks

Mechanics reference for all 58 perks. Exact numbers, interaction rules, and
selection conditions — no source paths or decompiler addresses.

See also: [Perk ID map](../perk-id-map.md) |
[Perk runtime reference](../re/static/perks-runtime-reference.md)

## Selection Metadata

`Base Modes` reflects only the static mode flags on each perk. Runtime offer
gates (Death Clock blocks, hardcore quest special-cases, weapon checks, rarity
gates) are listed below.

### Metadata Matrix

| ID | Perk | Stackable | Base Modes | Prereq | Unlocks |
| --- | --- | --- | --- | --- | --- |
| 0 | AntiPerk | No | Never offered | None | None |
| 1 | Bloody Mess / Quick Learner | No | Survival, Quest, 2P | None | None |
| 2 | Sharpshooter | No | Survival, Quest, 2P | None | None |
| 3 | Fastloader | No | Survival, Quest, 2P | None | None |
| 4 | Lean Mean Exp. Machine | No | Survival, Quest, 2P | None | None |
| 5 | Long Distance Runner | No | Survival, Quest, 2P | None | None |
| 6 | Pyrokinetic | No | Survival, Quest, 2P | None | None |
| 7 | Instant Winner | Yes | Survival, Quest, 2P | None | None |
| 8 | Grim Deal | No | Survival only | None | None |
| 9 | Alternate Weapon | No | Survival, Quest | None | None |
| 10 | Plaguebearer | No | Survival, Quest, 2P | None | None |
| 11 | Evil Eyes | No | Survival, Quest, 2P | None | None |
| 12 | Ammo Maniac | No | Survival, Quest, 2P | None | None |
| 13 | Radioactive | No | Survival, Quest, 2P | None | None |
| 14 | Fastshot | No | Survival, Quest, 2P | None | None |
| 15 | Fatal Lottery | Yes | Survival only | None | None |
| 16 | Random Weapon | Yes | Survival, Quest | None | None |
| 17 | Mr. Melee | No | Survival, Quest, 2P | None | None |
| 18 | Anxious Loader | No | Survival, Quest, 2P | None | None |
| 19 | Final Revenge | No | Survival only | None | None |
| 20 | Telekinetic | No | Survival, Quest, 2P | None | None |
| 21 | Perk Expert | No | Survival, Quest, 2P | None | Perk Master (43) |
| 22 | Unstoppable | No | Survival, Quest, 2P | None | None |
| 23 | Regression Bullets | No | Survival, Quest, 2P | None | None |
| 24 | Infernal Contract | No | Survival, Quest, 2P | None | None |
| 25 | Poison Bullets | No | Survival, Quest, 2P | None | None |
| 26 | Dodger | No | Survival, Quest, 2P | None | Ninja (40) |
| 27 | Bonus Magnet | No | Survival, Quest, 2P | None | None |
| 28 | Uranium Filled Bullets | No | Survival, Quest, 2P | None | None |
| 29 | Doctor | No | Survival, Quest, 2P | None | None |
| 30 | Monster Vision | No | Survival, Quest, 2P | None | None |
| 31 | Hot Tempered | No | Survival, Quest, 2P | None | None |
| 32 | Bonus Economist | No | Survival, Quest, 2P | None | None |
| 33 | Thick Skinned | No | Survival, Quest, 2P | None | None |
| 34 | Barrel Greaser | No | Survival, Quest, 2P | None | None |
| 35 | Ammunition Within | No | Survival, Quest, 2P | None | None |
| 36 | Veins of Poison | No | Survival, Quest, 2P | None | Toxic Avenger (37) |
| 37 | Toxic Avenger | No | Survival, Quest, 2P | Veins of Poison (36) | None |
| 38 | Regeneration | No | Survival, Quest, 2P | None | Greater Regeneration (45) |
| 39 | Pyromaniac | No | Survival, Quest, 2P | None | None |
| 40 | Ninja | No | Survival, Quest, 2P | Dodger (26) | None |
| 41 | Highlander | No | Survival only | None | None |
| 42 | Jinxed | No | Survival, Quest, 2P | None | None |
| 43 | Perk Master | No | Survival, Quest, 2P | Perk Expert (21) | None |
| 44 | Reflex Boosted | No | Survival, Quest, 2P | None | None |
| 45 | Greater Regeneration | No | Survival, Quest, 2P | Regeneration (38) | None |
| 46 | Breathing Room | No | Survival, 2P | None | None |
| 47 | Death Clock | No | Survival, Quest, 2P | None | None |
| 48 | My Favourite Weapon | No | Survival, Quest, 2P | None | None |
| 49 | Bandage | No | Survival, Quest, 2P | None | None |
| 50 | Angry Reloader | No | Survival, Quest, 2P | None | None |
| 51 | Ion Gun Master | No | Survival, Quest, 2P | None | None |
| 52 | Stationary Reloader | No | Survival, Quest, 2P | None | None |
| 53 | Man Bomb | No | Survival, Quest, 2P | None | None |
| 54 | Fire Cough | No | Survival, Quest, 2P | None | None |
| 55 | Living Fortress | No | Survival, Quest, 2P | None | None |
| 56 | Tough Reloader | No | Survival, Quest, 2P | None | None |
| 57 | Lifeline 50-50 | No | Survival, Quest, 2P | None | None |

### Additional Offer Gates

- Hardcore quest `2-10` blocks Poison Bullets (25), Veins of Poison (36), and
  Plaguebearer (10).
- Death Clock (47) active blocks Jinxed (42), Breathing Room (46), Grim Deal
  (8), Highlander (41), Fatal Lottery (15), Ammunition Within (35), Infernal
  Contract (24), Regeneration (38), Greater Regeneration (45), Thick Skinned
  (33), and Bandage (49).
- Pyromaniac (39) is only offerable while the current weapon is Flamethrower.
- Global 25% rarity reject gate applies to Jinxed (42), Ammunition Within (35),
  Anxious Loader (18), and Monster Vision (30).
- Quest `1-7` special case: Monster Vision (30) is forced as the first choice
  if not already owned.

### Progressions

- Dodger (26) -> Ninja (40)
- Veins of Poison (36) -> Toxic Avenger (37)
- Perk Expert (21) -> Perk Master (43)
- Regeneration (38) -> Greater Regeneration (45)

## 0. AntiPerk

Internal sentinel. Never offered to the player.

## 1. Bloody Mess / Quick Learner

+30% XP from creature kills. When blood effects are enabled, projectile hits
produce extra gore decals and blood particles. The perk's name and description
switch between "Bloody Mess" and "Quick Learner" depending on the blood toggle.

## 2. Sharpshooter

Nearly eliminates weapon spread (forced to a very low baseline) and adds a laser
sight. The trade-off is a 5% slower fire rate.

## 3. Fastloader

Reload time is 30% shorter (×0.7 multiplier).

## 4. Lean Mean Exp. Machine

Passive XP income: every 0.25 seconds, player 0 earns 10 × (times picked) XP.
Stacks linearly with itself.

## 5. Long Distance Runner

Movement speed continues ramping beyond the normal cap of 2.0, up to 2.8, as
long as the player keeps moving. Stopping causes speed to decay rapidly.

## 6. Pyrokinetic

While the crosshair is near a creature, Pyrokinetic decrements that creature's
shared collision timer. When it wraps, the timer is reset to 0.5 seconds and a
heat flare triggers — a burst of particles and a random decal at the target.
Purely visual; no damage.

## 7. Instant Winner

Immediately grants +2500 XP. Can be picked multiple times.

## 8. Grim Deal

Immediately grants +18% of current XP (rounded down), then kills the player.
Not offered in Quest mode or two-player sessions.

## 9. Alternate Weapon

Adds a second weapon slot. Press reload to swap between them. Carrying two
weapons reduces movement speed by 20%, and swapping adds a brief firing delay
(+0.1 s cooldown) to prevent instant swap-firing. Not offered in two-player
mode.

## 10. Plaguebearer

The player becomes a disease carrier. Nearby weak creatures (under 150 HP,
within 30 units) get infected. Infected creatures take 15 damage every 0.5
seconds, and the infection spreads to other creatures within 45 units. Each
infection kill increments a global counter that gradually suppresses further
spreading — the plague burns itself out over time. Shared across all players.
Suppressed in hardcore quest 2-10.

## 11. Evil Eyes

The creature nearest the crosshair (within 12 units) is frozen in place — no
AI, no movement — as long as it stays targeted.

## 12. Ammo Maniac

Clip size increases by 25% (at least +1 round). The bonus applies whenever a
weapon is assigned, so it persists across weapon swaps and reloads.

## 13. Radioactive

A green aura centered on player 0 damages creatures within 100 units. The
shared collision timer (0.5 s period) decrements at 1.5× rate, giving an
effective tick interval of 0.33 s. Damage scales with proximity:
(100 − distance) × 0.3. Kills from the aura award XP to player 0.

## 14. Fastshot

Fire rate is 12% faster (shot cooldown ×0.88).

## 15. Fatal Lottery

50/50 coin flip: either +10 000 XP or instant death. Can be picked multiple
times. Not offered in Quest mode or two-player sessions.

## 16. Random Weapon

Immediately assigns a random unlocked weapon, retrying up to 100 rolls to avoid
the pistol and the current weapon. Native edge case: if no valid roll appears
within those retries, the last roll is used anyway. Not available in two-player
mode. Can be picked multiple times.

## 17. Mr. Melee

When a creature hits the player in melee, the player automatically
counter-attacks for 25 damage. The player still takes the contact damage
normally.

## 18. Anxious Loader

During a reload, each fire press shaves 0.05 seconds off the remaining reload
time. Mash to reload faster.

## 19. Final Revenge

On death, the player explodes with a 512-unit blast radius. Damage falls off
linearly: (512 − distance) × 5. Not offered in Quest mode or two-player
sessions.

## 20. Telekinetic

Aim at a bonus pickup within 24 units for 650 ms to collect it remotely.

## 21. Perk Expert

Perk selection shows 6 choices instead of the default 5.

## 22. Unstoppable

Getting hit no longer disrupts aim or movement — no knockback, no spread
penalty. Damage still applies normally.

## 23. Regression Bullets

Lets the player fire during a reload by spending XP instead of ammo. Cost per
shot is based on weapon reload time: ×4 for fire-type weapons, ×200 otherwise.
XP can't go negative. Native quirk: the reload-fire path only runs while XP is
above 0. While this perk (or Ammunition Within) is active, reloads can't be
restarted mid-reload.

## 24. Infernal Contract

Immediately grants +3 levels and +3 pending perk picks, but drops every alive
player to 0.1 health. Not offered while Death Clock is active.

## 25. Poison Bullets

Each projectile hit has a 1-in-8 chance to poison the target. Poisoned creatures
take continuous damage (60/s) and show a red aura. Toxic Avenger's 180/s strong
poison comes from its melee-retaliation path, not bullet poisoning. Poison
ticks still trigger hit flash, but use zero impulse (no knockback). Suppressed
in hardcore quest 2-10.

## 26. Dodger

Each incoming hit has a 1-in-5 chance of being dodged entirely. If Ninja is also
owned, Ninja's better odds take over and Dodger does nothing.

## 27. Bonus Magnet

When a kill doesn't naturally spawn a bonus, Bonus Magnet gives a second chance
roll. Stacks with the pistol's built-in bonus boost.

## 28. Uranium Filled Bullets

Bullet damage is doubled (×2).

## 29. Doctor

Bullet damage is increased by 20% (×1.2). Also shows a health bar above the
creature nearest the crosshair, using the same targeting as Pyrokinetic and Evil
Eyes.

## 30. Monster Vision

Every creature gets a yellow highlight behind it, making them easy to spot.
Creature shadows are hidden while this perk is active.

## 31. Hot Tempered

Periodically fires an 8-shot ring of plasma projectiles (alternating Plasma
Minigun and Plasma Rifle) centered on the player. The interval is randomized
between 2 and 9 seconds after each burst. Friendly fire applies when enabled.

## 32. Bonus Economist

Timed bonus pickups last 50% longer.

## 33. Thick Skinned

On pick, every alive player's health drops to 2/3 (minimum 1). In exchange, all
incoming damage is permanently reduced to 2/3. The damage reduction is applied
before dodge rolls. Not offered while Death Clock is active.

## 34. Barrel Greaser

Bullet damage is increased by 40% (×1.4) and bullets travel at double speed.

## 35. Ammunition Within

Lets the player fire during a reload by paying health instead of ammo. Cost per
shot is 1 HP normally, 0.15 HP for fire-type weapons. The health cost goes
through normal damage processing, so Thick Skinned, Dodger, and Ninja can
reduce or negate it. If Regression Bullets is also owned, it takes priority
(XP cost instead of health). Native quirk: this path also requires XP above 0.
Reloads can't be restarted mid-reload.

## 36. Veins of Poison

When a creature hits the player in melee and the shield bonus isn't active, that
creature gets poisoned (weak tick, 60 damage/s). Suppressed in hardcore quest
2-10.

## 37. Toxic Avenger

Upgraded version of Veins of Poison — melee attackers receive strong poison
(180 damage/s) instead of weak. Requires Veins of Poison.

## 38. Regeneration

Heals each alive player toward 100 HP. The heal ticks every other frame
(50% chance per frame) for +dt health. Only triggers between 0 and 100 HP.

## 39. Pyromaniac

Fire weapon damage is increased by 50% (×1.5). Only offered when the current
weapon is the Flamethrower.

## 40. Ninja

Each incoming hit has a 1-in-3 chance of being dodged entirely. Overrides Dodger
when both are owned. Requires Dodger.

## 41. Highlander

Damage no longer reduces health. Instead, every hit has a flat 10% chance of
instant death. Hit disruption (knockback, spread penalty) still applies unless
Unstoppable is active. Not offered in Quest mode or two-player sessions, and
blocked while Death Clock is active.

## 42. Jinxed

Random events on a global timer (randomized 2–4 second interval): 10% chance of
taking 5 self-damage, and — if the Freeze bonus isn't active — a random creature
may instantly die, awarding its XP.

## 43. Perk Master

Perk selection shows 7 choices instead of the default 5 (or 6 with Perk Expert).
Requires Perk Expert.

## 44. Reflex Boosted

The entire game world runs 10% slower (frame time ×0.9). Effectively a global
slow-motion effect.

## 45. Greater Regeneration

No runtime effect has been found in this build — appears to be a no-op. Death
Clock clears it on pick. Requires Regeneration.

## 46. Breathing Room

Not available in quest mode. On pick, every alive player's health drops to 1/3,
and every creature on screen is killed instantly without awarding XP.

## 47. Death Clock

On pick, health is set to 100 and Regeneration / Greater Regeneration are
cleared. For the next 30 seconds, damage routed through normal
`player_take_damage` paths is ignored, but health drains steadily to zero
(100 HP over 30 s). Projectile hits still apply their fixed hit damage.
Medikits stop spawning, and perks that would undermine the clock
(Regeneration, Thick Skinned, Highlander, Jinxed, etc.) are blocked from
selection.

## 48. My Favourite Weapon

+2 clip size on pick and on every future weapon assignment. Weapon bonus pickups
are disabled entirely — they won't spawn and can't be collected.

## 49. Bandage

Multiplies every alive player's health by a random value from 1 to 50, then
clamps to 100. Each player gets an independent roll. Produces a burst of
particles per player.

## 50. Angry Reloader

Halfway through a reload (when the timer crosses 50%), fires a ring of Plasma
Minigun projectiles centered on the player. The ring size scales with reload
time: 7 + (reload time × 4) projectiles. Only triggers when reload time exceeds
0.5 s. Benefits from Stationary Reloader's 3× reload speed. Friendly fire
applies when enabled.

## 51. Ion Gun Master

Ion weapon damage and blast radius are both increased by 20% (×1.2). The damage
bonus is global — any ion damage is scaled, regardless of which player owns the
perk.

## 52. Stationary Reloader

Reload speed triples (×3) while standing still.

## 53. Man Bomb

Standing still charges an explosion timer (starts at 4 seconds). When it fires,
8 ion projectiles spray out in a ring with slight angular jitter, alternating Ion
Minigun and Ion Rifle. Moving resets the timer to zero. Friendly fire applies
when enabled.

## 54. Fire Cough

Every 2–5 seconds (randomized), involuntarily fires a single Fire Bullets
projectile from the muzzle, complete with weapon fire sound effects and a small
smoke sprite. The shot inherits the current weapon spread. Friendly fire applies
when enabled.

## 55. Living Fortress

While standing still, a timer ramps up over 30 seconds. Bullet damage is
multiplied by (timer × 0.05 + 1), reaching up to ×2.5 at full charge. Moving
resets the timer. In multiplayer, the bonus stacks — each alive player with a
charged timer contributes their own multiplier.

## 56. Tough Reloader

Damage taken while reloading is halved (×0.5).

## 57. Lifeline 50-50

On pick, every other creature on screen is instantly removed (no XP
awarded). The selection alternates through creature pool slots, skipping
creatures with more than 500 HP or special flags.
