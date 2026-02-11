---
icon: lucide/sparkles
tags:
  - mechanics
  - systems
  - perks
---

# Perks

Perks are passive abilities chosen on level-up. The player picks one from a
random selection of 5 (or more with Perk Expert / Perk Master). Most perks are
permanent, some are instant one-shots, and a few carry harsh trade-offs. In
two-player mode, perk counts are shared: picking a perk on either player grants
it to both.

This page documents all 58 perks with exact numbers and interaction rules.
For decompiler-level details on where each perk runs in the game loop, see
[Perk runtime reference](../re/static/perks-runtime-reference.md).

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

Generates 10 XP every 0.25 seconds. Stacks linearly with itself.

## 5. Long Distance Runner

Movement speed continues ramping beyond the normal cap of 2.0, up to 2.8, as
long as the player keeps moving. Stopping causes speed to decay rapidly.

## 6. Pyrokinetic

While the crosshair is near a creature, Pyrokinetic decrements that creature's
shared collision timer. When it wraps, the timer resets to 0.5 seconds and a
heat flare triggers: a burst of particles and a random decal at the target.
Purely visual; no damage.

!!! question "Cross-version check"
    Verify other game versions/builds to confirm whether the no-damage behavior
    is original design or a regression in this release.

## 7. Instant Winner

Immediately grants +2500 XP. Can be picked multiple times.

## 8. Grim Deal

Immediately grants +18% of current XP, then kills the player.

Not offered in quest mode or two-player sessions.

## 9. Alternate Weapon

Adds a second weapon slot. Press reload to swap between them. Carrying two
weapons reduces movement speed by 20%, and swapping adds a brief firing delay
(+0.1 s cooldown) to prevent instant swap-firing.

Not offered in two-player mode.

## 10. Plaguebearer

The player becomes a disease carrier. Nearby weak creatures (under 150 HP,
within 30 units) get infected. Infected creatures take 15 damage every 0.5
seconds, and the infection spreads to other creatures within 45 units. Each
infection kill increments a global counter that gradually suppresses further
spreading. The plague burns itself out over time. Shared across all players.

Suppressed in hardcore quest 2.10.

## 11. Evil Eyes

The creature nearest the crosshair (within 12 units) is frozen in place (no
AI, no movement) as long as it stays targeted.

## 12. Ammo Maniac

Clip size increases by 25% (at least +1 round). The bonus applies whenever a
weapon is assigned, so it persists across weapon swaps and reloads.

## 13. Radioactive

A green aura damages creatures within 100 units. The shared collision timer
(0.5 s period) decrements at 1.5× rate, giving an effective tick interval of
0.33 s. Damage scales with proximity: (100 − distance) × 0.3. Kills from the
aura award XP directly.

## 14. Fastshot

Fire rate is 12% faster (shot cooldown ×0.88).

## 15. Fatal Lottery

50/50 coin flip: either +10 000 XP or instant death. Can be picked multiple
times.

Not offered in quest mode or two-player sessions.

## 16. Random Weapon

Immediately assigns a random unlocked weapon (never the pistol, never the
current weapon). Can be picked multiple times.

Not available in two-player mode.

## 17. Mr. Melee

When a creature hits the player in melee, the player automatically
counter-attacks for 25 damage. The player still takes the contact damage
normally.

## 18. Anxious Loader

During a reload, each fire press shaves 0.05 seconds off the remaining reload
time. Mash to reload faster.

## 19. Final Revenge

On death, the player explodes with a 512-unit blast radius. Damage falls off
linearly: (512 − distance) × 5.

Not offered in quest mode or two-player sessions.

## 20. Telekinetic

Aim at a bonus pickup within 24 units for 650 ms to collect it remotely.

## 21. Perk Expert

Perk selection shows 6 choices instead of 5.

Unlocks [Perk Master](#43-perk-master).

## 22. Unstoppable

Getting hit no longer disrupts aim or movement: no knockback, no spread
penalty. Damage still applies normally.

## 23. Regression Bullets

Lets the player fire during a reload by spending XP instead of ammo. Cost per
shot is based on weapon reload time: ×4 for fire-type weapons, ×200 otherwise.
XP can't go negative. While this perk (or Ammunition Within) is active, reloads
can't be restarted mid-reload.

## 24. Infernal Contract

Immediately grants +3 levels and +3 pending perk picks, but drops every alive
player to 0.1 health.

Not offered while Death Clock is active.

## 25. Poison Bullets

Each projectile hit has a 1-in-8 chance to poison the target. Poisoned creatures
take continuous damage (60/s normally, 180/s with [Toxic Avenger](#37-toxic-avenger)) and show a red
aura. Poison damage triggers normal hit effects like flash and knockback.

Suppressed in hardcore quest 2.10.

## 26. Dodger

Each incoming hit has a 1-in-5 chance of being dodged entirely. If
[Ninja](#40-ninja) is also owned, Ninja's better odds take over and Dodger does
nothing.

Unlocks [Ninja](#40-ninja).

## 27. Bonus Magnet

When a kill doesn't naturally spawn a bonus, Bonus Magnet gives a second chance
roll. Stacks with the pistol's built-in bonus boost.

## 28. Uranium Filled Bullets

Bullet damage is doubled (×2).

Unlocked by quest 1.3 (*Target Practice*).

## 29. Doctor

Bullet damage is increased by 20% (×1.2). Also shows a health bar below the
creature nearest the crosshair, using the same targeting as Pyrokinetic and Evil
Eyes.

Unlocked by quest 1.5 (*Alien Dens*).

## 30. Monster Vision

Every creature gets a yellow highlight behind it, making them easy to spot.
Creature shadows are hidden while this perk is active.


Unlocked by quest 1.7 (*Spider Wave Syndrome*).

## 31. Hot Tempered

Periodically fires an 8-shot ring of plasma projectiles (alternating Plasma
Minigun and Plasma Rifle) centered on the player. The interval is randomized
between 2 and 9 seconds after each burst. Friendly fire applies when enabled.

Unlocked by quest 1.9 (*Nesting Grounds*).

## 32. Bonus Economist

Timed bonus pickups last 50% longer.

Unlocked by quest 2.1 (*Everred Pastures*).

## 33. Thick Skinned

On pick, every alive player's health drops to 2/3 (minimum 1). In exchange, all
incoming damage is permanently reduced to 2/3. The damage reduction is applied
before dodge rolls.

Not offered while Death Clock is active.

Unlocked by quest 2.3 (*Arachnoid Farm*).

## 34. Barrel Greaser

Bullet damage is increased by 40% (×1.4) and bullets travel at double speed.

Unlocked by quest 2.5 (*Sweep Stakes*).

## 35. Ammunition Within

Lets the player fire during a reload by paying health instead of ammo. Cost per
shot is 1 HP normally, 0.15 HP for fire-type weapons. The health cost goes
through normal damage processing, so Thick Skinned, Dodger, and Ninja can
reduce or negate it. If Regression Bullets is also owned, it takes priority
(XP cost instead of health). Reloads can't be restarted mid-reload.

Unlocked by quest 2.7 (*Survival Of The Fastest*).

## 36. Veins of Poison

When a creature hits the player in melee and the shield bonus isn't active, that
creature gets poisoned (60 damage/s).

Suppressed in hardcore quest 2.10.

Unlocks [Toxic Avenger](#37-toxic-avenger).
Unlocked by quest 2.9 (*Ghost Patrols*).

## 37. Toxic Avenger

Upgrades [Veins of Poison](#36-veins-of-poison). Melee attackers
receive strong poison (180 damage/s) instead of weak.

Requires [Veins of Poison](#36-veins-of-poison).
Unlocked by quest 3.1 (*The Blighting*).

## 38. Regeneration

Heals each alive player toward 100 HP at 0.5 HP/s. Every frame has a 50%
chance to heal +dt HP. Only triggers between 0 and 100 HP.

Unlocks [Greater Regeneration](#45-greater-regeneration).
Unlocked by quest 3.3 (*The Killing*).

## 39. Pyromaniac

Fire weapon damage is increased by 50% (×1.5).

Only offered when the current weapon is the Flamethrower.

Unlocked by quest 3.5 (*Surrounded By Reptiles*).

## 40. Ninja

Each incoming hit has a 1-in-3 chance of being dodged entirely. Overrides
[Dodger](#26-dodger) when both are owned.

Requires [Dodger](#26-dodger).
Unlocked by quest 3.7 (*Spiders Inc.*).

## 41. Highlander

Damage no longer reduces health. Instead, every hit has a flat 10% chance of
instant death. Hit disruption (knockback, spread penalty) still applies unless
Unstoppable is active.

Not offered in quest mode or two-player sessions.

Unlocked by quest 3.9 (*Deja vu*).

## 42. Jinxed

Random events on a global timer (randomized 2–4 second interval): 10% chance of
taking 5 self-damage, and if the Freeze bonus isn't active, a random creature
may instantly die, awarding its XP.

Unlocked by quest 4.1 (*Major Alien Breach*).

## 43. Perk Master

Perk selection shows 7 choices instead of 5 (or 6 with
[Perk Expert](#21-perk-expert)).

Requires [Perk Expert](#21-perk-expert).
Unlocked by quest 4.3 (*Lizard Zombie Pact*).

## 44. Reflex Boosted

The entire game world runs 10% slower (frame time ×0.9). Effectively a global
slow-motion effect.

Unlocked by quest 4.5 (*The Massacre*).

## 45. Greater Regeneration

Upgrades [Regeneration](#38-regeneration): when a regen tick triggers, heal
amount is doubled (+2×dt instead of +dt), for an effective average heal rate
of about 1 HP/s.
[Death Clock](#47-death-clock) clears it on pick.

!!! bug "Original bug"
    In the original executable, Greater Regeneration has no runtime effect.
    Run with `--preserve-bugs` to keep that no-op behavior for parity.

Requires [Regeneration](#38-regeneration).
Unlocked by quest 4.7 (*Gauntlet*).

## 46. Breathing Room

On pick, every alive player's health drops to 1/3,
and every creature on screen is killed instantly without awarding XP.

Unlocked by quest 4.9 (*The Annihilation*).

## 47. Death Clock

On pick, health is set to 100 and Regeneration / Greater Regeneration are
cleared. For the next 30 seconds the player is immune to all other damage, but
health drains steadily to zero (100 HP over 30 s). Medikits stop spawning, and
perks that would undermine the clock (Regeneration, Thick Skinned, Highlander,
Jinxed, etc.) are blocked from selection.

Unlocked by quest 5.2 (*The Spanking Of The Dead*).

## 48. My Favourite Weapon

+2 clip size on pick and on every future weapon assignment. Weapon bonus pickups
are disabled entirely. They won't spawn and can't be collected.

Unlocked by quest 5.3 (*The Fortress*).

## 49. Bandage

Restores each alive player's health by a random amount from +1 to +50 HP
(1-50% of the full 100-HP bar), then clamps to 100. Each player gets an
independent roll.

!!! bug "Original behavior"
    The original executable multiplies health by ×1..×50 instead of restoring
    +1..+50 HP. Use `--preserve-bugs` to keep that native behavior.

Unlocked by quest 5.5 (*Knee-deep in the Dead*).

## 50. Angry Reloader

Halfway through a reload (when the timer crosses 50%), fires a ring of Plasma
Minigun projectiles centered on the player. Projectile count is
`7 + floor(reload time × 4)` (for example: `15` projectiles at a `2.0 s` reload).
Only triggers when reload time exceeds 0.5 s. Benefits from Stationary Reloader's
3× reload speed. Friendly fire applies when enabled.

Unlocked by quest 5.6 (*Cross Fire*).

## 51. Ion Gun Master

Ion weapon damage and blast radius are both increased by 20% (×1.2). The damage
bonus is global: any ion damage is scaled, regardless of which player owns the
perk.

Unlocked by quest 5.8 (*Monster Blues*).

## 52. Stationary Reloader

Reload speed triples (×3) while standing still.

Unlocked by quest 5.9 (*Nagolipoli*).

## 53. Man Bomb

Standing still charges an explosion timer (starts at 4 seconds). When it fires,
8 ion projectiles spray out in a ring with slight angular jitter, alternating Ion
Minigun and Ion Rifle. Moving resets the timer to zero after this check. In
practice that means a very long moving frame can still trigger one burst before
the reset. Friendly fire applies when enabled.

## 54. Fire Cough

Every 2–5 seconds (randomized), involuntarily fires a single Fire Bullets
projectile from the muzzle, complete with weapon fire sound effects and a small
smoke sprite. The shot inherits the current weapon spread. Friendly fire applies
when enabled.

## 55. Living Fortress

While standing still, a timer ramps up over 30 seconds. Bullet damage is
multiplied by (timer × 0.05 + 1), reaching up to ×2.5 at full charge. Moving
resets the timer. In multiplayer, the bonus stacks: each alive player with a
charged timer contributes their own multiplier.

## 56. Tough Reloader

Damage taken while reloading is halved (×0.5).

## 57. Lifeline 50-50

On pick, every other creature on screen is instantly removed (no XP
awarded). The selection alternates through creature pool slots, skipping
creatures with more than 500 HP or special flags.
