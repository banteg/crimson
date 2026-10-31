---
icon: lucide/sparkles
tags:
  - mechanics
  - systems
  - perks
---

# Perks

Each level-up lets you pick one of 57 perks from 5 random choices (6 with
Perk Expert, 7 with Perk Master). Most perks are permanent, a few are
one-shots, and some carry harsh trade-offs. In two-player mode both players
share one set of perks: a pick applies to both. Perks exist in Survival and
Quests; Rush and Typ-o Shooter have none.

"Bullet damage" below means any gun projectile's direct hit: bullets, plasma,
direct ion hits, Fire Bullets and the perk rings. It excludes flames,
explosions, ion blasts, poison and Mr. Melee. Enemy shots always deal a flat
10 that only Shield (and Death Clock) blocks; no other perk reduces or dodges
them.

## How perk offers work

- Each level-up banks one pick. Picks wait until you open the perk prompt,
  and you can bank several. In quests, each unspent pick takes 1 s off your
  final time.
- The choices are rolled when you open the menu and stay fixed until you
  pick one.
- A perk you own isn't offered again, except Instant Winner, Fatal Lottery
  and Random Weapon.
- Perks 1–27, Man Bomb, Fire Cough, Living Fortress and Tough Reloader are
  always available. The rest unlock by finishing quests, as listed below.
- A run on the [1.9.8 rules](../rewrite/rules-1.9.8.md) never offers Man Bomb, Fire Cough, Living Fortress or
  Tough Reloader, which 1.9.8 lacks.
- Toxic Avenger, Ninja, Perk Master and Greater Regeneration need their base
  perk first.
- Jinxed, Ammunition Within, Anxious Loader and Monster Vision are rare:
  each roll that lands on one is thrown back 25% of the time.
- Pyromaniac is only offered while you hold the Flamethrower.
- Once you have Death Clock, these are never offered: Jinxed, Breathing Room,
  Grim Deal, Highlander, Fatal Lottery, Ammunition Within, Infernal Contract,
  Regeneration, Greater Regeneration, Thick Skinned and Bandage.
- Some perks are not offered in quest mode, two-player mode or hardcore
  quest 2.10 (noted per perk). Quest 3.4 (*Hidden Evil*) always offers
  Monster Vision first until you own it.
- The Tutorial always offers Sharpshooter, Long Distance Runner, Evil Eyes,
  Radioactive and Fastshot.

## 1. Bloody Mess / Quick Learner

+30% XP from creature kills. With blood on, projectile hits also spray extra
gore. With blood turned off the perk is called Quick Learner.

## 2. Sharpshooter

Locks weapon spread at a low constant: it no longer grows from sustained fire
or from getting hit. Adds a laser sight. The trade-off: shots take 5% longer
to cycle (×1.05).

## 3. Fastloader

Reload time is 30% shorter (×0.7 multiplier).

## 4. Lean Mean Exp. Machine

Generates 10 XP every 0.25 seconds: 40 XP a second for the rest of the run.

## 5. Long Distance Runner

Keep moving and your top speed climbs past the normal cap: 2.0 → 2.8 (+40%)
over about 0.8 s more running. Stopping loses it at once.

## 6. Pyrokinetic

Hold your crosshair on a creature and it flares every 0.5 s: five flames and a
scorch mark. The flames are the same fire particles flame weapons spit: each
one burns the first creature it touches for up to 8 damage (less as it cools)
and chars it darker. A held target takes up to ~23 damage per flare, ×1.5 with
[Pyromaniac](#39-pyromaniac).

!!! bug "Original bug"
    In the original executable, co-op targeting uses player 1's crosshair
    only. Use `--preserve-bugs` to keep that.

## 7. Instant Winner

Immediately grants +2500 XP. Can be picked multiple times.

## 8. Grim Deal

Immediately grants +18% of current XP, then kills the player.

Not offered in quest mode or two-player mode.

## 9. Alternate Weapon

Adds a second weapon slot. The reload key swaps slots, so you can't reload by
hand: a weapon reloads only when its clip runs dry, and a stowed weapon's
reload pauses until you swap back. Owning the perk slows movement by 20%, and
each swap adds 0.1 s before you can fire.

Not offered in two-player mode.

## 10. Plaguebearer

Creatures under 150 HP that come within 30 units of you catch the plague.
Infected creatures flee, take 15 damage every 0.5 s, and pass it on to
creatures under 150 HP within 45 units. Plague kills count as normal kills
(full XP, bonus drops).

After 50 plague kills in a run you stop infecting creatures by touch; after 60
the plague stops spreading. Infections already running keep burning. In co-op
both players carry it.

Not offered in hardcore quest 2.10.

!!! bug "Original bug"
    In the original executable, only player 1 infects creatures by touch in
    co-op. Use `--preserve-bugs` to keep that.

## 11. Evil Eyes

The creature under your crosshair freezes in place and can't attack while you
hold it there.

!!! bug "Original bug"
    In the original executable, co-op targeting uses player 1's crosshair
    only. Use `--preserve-bugs` to keep that.

## 12. Ammo Maniac

Clip size +25% (at least +1 round) on every weapon you get. Taking it refills
your clip.

## 13. Radioactive

A green aura hurts creatures within 100 units of you: (100 − distance) × 0.3
damage three times a second, up to 90 damage/s point-blank. Aura kills give
base XP only (no Bloody Mess bonus, no Double Experience) and never drop
bonuses. Lizards can't be finished off: the aura leaves them at 1 HP. In a
run on the [1.9.8 rules](../rewrite/rules-1.9.8.md), the aura kills lizards too.

!!! bug "Original bug"
    In the 1.9.8 executable, the aura also burns creatures that are already
    dead and pays their XP again. Use `--preserve-bugs` to keep that in a run
    on the 1.9.8 rules.

## 14. Fastshot

12% less time between shots (×0.88): about 14% more shots per second.

## 15. Fatal Lottery

50/50 coin flip: either +10 000 XP or instant death. Can be picked multiple
times.

Not offered in quest mode or two-player mode.

## 16. Random Weapon

Immediately gives a random unlocked weapon (never the pistol, never your
current one). Can be picked multiple times.

Not offered in two-player mode.

## 17. Mr. Melee

When a creature hits the player in melee, the player automatically
counter-attacks for 25 damage. The player still takes the contact damage
normally.

## 18. Anxious Loader

During a reload, each fire press shaves 0.05 seconds off the remaining reload
time. Mash to reload faster.

## 19. Final Revenge

When a creature's attack (or an Ammunition Within shot) kills you, you explode:
every creature within 512 units takes (512 − distance) × 5 damage, up to 2560
point-blank. Its kills drop no bonuses. Dying to enemy shots, Death Clock,
Jinxed, Fatal Lottery or Grim Deal doesn't trigger it.

Not offered in quest mode or two-player mode.

!!! bug "Original bug"
    In the original executable, a Highlander death doesn't trigger Final
    Revenge. Use `--preserve-bugs` to keep that.

## 20. Telekinetic

Hold your crosshair within 24 units of a bonus for 0.65 s to collect it from
afar.

## 21. Perk Expert

Perk selection shows 6 choices instead of 5.

Leads to [Perk Master](#43-perk-master).

## 22. Unstoppable

Hits no longer jolt your heading or widen your spread. Damage still applies.

## 23. Regression Bullets

Lets you keep firing during a reload, paying XP instead of ammo. Each shot
costs 200 XP per second of the weapon's base reload time (240 for the Assault
Rifle), or 4 per second for flamers (8 for the Flamethrower). Needs XP above
0, and XP never goes negative. Firing this way doesn't restart the reload.

## 24. Infernal Contract

Immediately grants +3 levels and +3 perk picks, but drops every living player
to 0.1 health.

!!! bug "Original bug"
    In the 1.9.8 executable, Infernal Contract sets only player 1's health to
    0.1, bringing them back if they were dead, and leaves player 2's alone.
    Use `--preserve-bugs` to keep that in a run on the 1.9.8 rules.

## 25. Poison Bullets

Each projectile hit has a 1-in-8 chance to poison the target. Poisoned
creatures glow red and take 60 damage/s until they die.
[Toxic Avenger](#37-toxic-avenger) doesn't strengthen bullet poison.

Not offered in hardcore quest 2.10.

## 26. Dodger

Each creature attack has a 1-in-5 chance to miss entirely. Enemy shots can't
be dodged. If you also own [Ninja](#40-ninja), its better odds take over.

Leads to [Ninja](#40-ninja).

## 27. Bonus Magnet

When the normal 1-in-9 bonus roll fails, Bonus Magnet rolls again at 1-in-10:
about 1 kill in 5 drops something instead of 1 in 9. It doesn't affect the
pistol's forced weapon drops.

## 28. Uranium Filled Bullets

Bullet damage is doubled (×2).

Unlocked by quest 1.3 (*Target Practice*).

## 29. Doctor

Bullet damage +20% (×1.2). Also shows a health bar below the creature under
your crosshair.

!!! bug "Original bug"
    In the original executable, co-op targeting uses player 1's crosshair
    only. Use `--preserve-bugs` to keep that.

Unlocked by quest 1.5 (*Alien Dens*).

## 30. Monster Vision

Every creature gets a yellow highlight behind it, making them easy to spot.
Creature shadows are hidden while this perk is active. Quest 3.4 (*Hidden
Evil*) always offers it first until you own it.

Unlocked by quest 1.7 (*Spider Wave Syndrome*).

## 31. Hot Tempered

Every 2–9 seconds (random), fires an 8-shot ring of plasma around you,
alternating Plasma Minigun and Plasma Rifle. While you have Fire Bullets, the
ring is Fire Bullets instead. Friendly fire applies when enabled.

In co-op, each player owns the next random interval as well as elapsed time. Under
`--preserve-bugs`, either player's burst re-rolls the threshold for both.

Unlocked by quest 1.9 (*Nesting Grounds*).

## 32. Bonus Economist

Timed bonus pickups last 50% longer.

Unlocked by quest 2.1 (*Everred Pastures*).

## 33. Thick Skinned

On pick, every living player loses 1/3 of their health. In exchange, creature
attacks deal about 2/3 damage (×0.666) for the rest of the run. Enemy shots
still hit for the full 10.

Unlocked by quest 2.3 (*Arachnoid Farm*).

## 34. Barrel Greaser

Bullet damage +40% (×1.4), and your gun projectiles fly twice as fast (not
rockets or flames).

Unlocked by quest 2.5 (*Sweep Stakes*).

## 35. Ammunition Within

Lets you keep firing during a reload, paying health instead of ammo: 1 HP per
shot, 0.15 HP with flamers. The cost counts as a creature hit: Tough Reloader
halves it (you're always reloading), Thick Skinned trims it, Dodger and Ninja
can dodge it, Shield and Death Clock make it free, and with Highlander every
shot is a 10% death roll. If you also own Regression Bullets, that takes
priority (XP instead of health). Firing this way doesn't restart the reload.

Unlocked by quest 2.7 (*Survival Of The Fastest*).

## 36. Veins of Poison

When a creature hits the player in melee and the shield bonus isn't active, that
creature gets poisoned (60 damage/s).

Not offered in hardcore quest 2.10.

Leads to [Toxic Avenger](#37-toxic-avenger).
Unlocked by quest 2.9 (*Ghost Patrols*).

## 37. Toxic Avenger

Upgrades [Veins of Poison](#36-veins-of-poison): melee attackers get strong
poison (180 damage/s) instead. Bullet poison stays weak.

Requires [Veins of Poison](#36-veins-of-poison).
Unlocked by quest 3.1 (*The Blighting*).

## 38. Regeneration

Heals each living player 0.5 HP per second on average, up to 100 HP.

!!! bug "Original bug"
    In the original executable, Regeneration heals only player 1, twice as
    fast in co-op. Use `--preserve-bugs` to keep that.

Leads to [Greater Regeneration](#45-greater-regeneration).
Unlocked by quest 3.3 (*The Killing*).

## 39. Pyromaniac

Flame damage ×1.5: Flamethrower, Blow Torch, HR Flamer and
[Pyrokinetic](#6-pyrokinetic) flares. Fire Bullets count as bullets.

Offered only while you hold the Flamethrower. In co-op it's offered when any
living player holds it.

!!! bug "Original bug"
    In the original executable, only player 1's weapon counts for the offer.
    Use `--preserve-bugs` to keep that.

Unlocked by quest 3.5 (*Surrounded By Reptiles*).

## 40. Ninja

Each creature attack has a 1-in-3 chance to miss entirely. Replaces
[Dodger](#26-dodger)'s odds.

Requires [Dodger](#26-dodger).
Unlocked by quest 3.7 (*Spiders Inc.*).

## 41. Highlander

Creature attacks no longer hurt. Instead each one has a flat 10% chance to
kill you outright. Dodger and Ninja dodges skip the roll. Enemy shots still
hit for 10.

Not offered in quest mode or two-player mode.

Unlocked by quest 3.9 (*Deja vu*).

## 42. Jinxed

Every 2–4 seconds: a 1-in-10 chance you lose 5 HP (nothing blocks it), and,
unless Freeze is active, a random creature may drop dead whatever its health.
Jinxed kills give base XP only and never drop bonuses.
In the default rules, only living creatures can be selected; corpses are
retried within the same ten-retry limit as empty slots.

!!! bug "Original bug"
    In the original executable, the 5 HP accident always hits player 1 in
    co-op, and the random kill can select a corpse and pay its XP again.
    Use `--preserve-bugs` to keep those behaviors.

!!! bug "Original bug"
    In the 1.9.8 executable, the random kill happens during Freeze too. Use
    `--preserve-bugs` to keep that in a run on the 1.9.8 rules.

Unlocked by quest 4.1 (*Major Alien Breach*).

## 43. Perk Master

Perk selection shows 7 choices instead of 5 (or 6 with
[Perk Expert](#21-perk-expert)).

Requires [Perk Expert](#21-perk-expert).
Unlocked by quest 4.3 (*Lizard Zombie Pact*).

## 44. Reflex Boosted

Everything runs at 90% speed, you included, so you get more real time to
react. Bonus timers and the clock stretch with it.

Unlocked by quest 4.5 (*The Massacre*).

## 45. Greater Regeneration

Doubles [Regeneration](#38-regeneration)'s healing: about 1 HP per second on
average. [Death Clock](#47-death-clock) removes it.

!!! bug "Original bug"
    In the original executable, Greater Regeneration does nothing. Use
    `--preserve-bugs` to keep that.

Requires [Regeneration](#38-regeneration).
Unlocked by quest 4.7 (*Gauntlet*).

## 46. Breathing Room

On pick, every player loses 2/3 of their health, and every creature in the
arena dies, with no XP and no bonus drops.

Not offered in quest mode.

Unlocked by quest 4.9 (*The Annihilation*).

## 47. Death Clock

On pick, health is set to 100 and Regeneration and Greater Regeneration are
removed. Creature attacks and enemy shots can't hurt you, but health drains
to zero over 30 s (3.33 HP/s): you die exactly 30 s later. Medikits stop
dropping, and 11 perks are no longer offered (see
[How perk offers work](#how-perk-offers-work)). An Ammunition Within you
already own fires for free; Jinxed accidents still cost 5 HP.

!!! bug "Original bug"
    In the original executable, enemy shots still hit for 10 during Death
    Clock. Use `--preserve-bugs` to keep that.

Unlocked by quest 5.2 (*The Spanking Of The Dead*).

## 48. My Favourite Weapon

+2 clip size, now and on every weapon you get later. Weapon bonuses stop
dropping.

!!! bug "Original bug"
    In the 1.9.8 executable, only the weapon you hold when you take the perk
    gets the +2: the next weapon you get loses it, even Ammo Maniac's
    reassignment. Holding the Pistol still brings Weapon bonuses. Use
    `--preserve-bugs` to keep those in a run on the 1.9.8 rules.

Unlocked by quest 5.3 (*The Fortress*).

## 49. Bandage

Each living player heals a random 1–50 HP (rolled separately), up to 100.

!!! bug "Original bug"
    In the original executable, Bandage multiplies health by 1–50 instead of
    adding 1–50 HP. Use `--preserve-bugs` to keep that.

Unlocked by quest 5.5 (*Knee-deep in the Dead*).

## 50. Angry Reloader

Halfway through a reload, fires a ring of Plasma Minigun shots: 7 + 4 per
second of reload, rounded down (15 for a 2 s reload). Fastloader and Weapon
Power Up shorten the reload and shrink the ring; Stationary Reloader just gets
you there sooner. Reloads of 0.5 s or less (the Pulse Gun's 0.1 s) never
trigger it. In a run on the [1.9.8 rules](../rewrite/rules-1.9.8.md), every reload triggers it,
the short ones included. Friendly fire applies when enabled.

Unlocked by quest 5.6 (*Cross Fire*).

## 51. Ion Gun Master

Ion blasts deal 20% more damage over a 20% wider radius (×1.2 each), Man
Bomb's included. Direct ion hits count as bullets.

Unlocked by quest 5.8 (*Monster Blues*).

## 52. Stationary Reloader

Reload speed triples (×3) while standing still.

!!! bug "Original bug"
    In the original executable, a reload sped up this way can finish without
    refilling the clip, leaving you one shot per reload. Use
    `--preserve-bugs` to keep that.

Unlocked by quest 5.9 (*Nagolipoli*).

## 53. Man Bomb

Every 4 seconds you stand still, you burst 8 ion shots in a ring (alternating
Ion Minigun and Ion Rifle, slightly jittered). Moving resets the count. While
you have Fire Bullets, the ring is Fire Bullets instead. Friendly fire applies
when enabled.

Always available, except in a run on the [1.9.8 rules](../rewrite/rules-1.9.8.md),
which never offers it.

## 54. Fire Cough

Every 2–5 seconds (random), you cough a Fire Bullets shot from the muzzle
toward your crosshair, with your current spread. Friendly fire applies when
enabled.

In co-op, each player owns their timer and next random interval, as with Hot
Tempered. `--preserve-bugs` retains the shared interval.

Always available, except in a run on the [1.9.8 rules](../rewrite/rules-1.9.8.md),
which never offers it.

## 55. Living Fortress

Standing still builds bullet damage by 5% a second, up to ×2.5 after 30 s.
Moving resets it. In co-op the bonuses multiply: each living player's charge
counts.

Always available, except in a run on the [1.9.8 rules](../rewrite/rules-1.9.8.md),
which never offers it.

## 56. Tough Reloader

Creature attacks deal half damage (×0.5) while you're reloading.

Always available, except in a run on the [1.9.8 rules](../rewrite/rules-1.9.8.md),
which never offers it.

## 57. Lifeline 50-50

Instantly removes every other creature in the arena (roughly half), with no XP
and no corpses. Creatures above 500 HP and nests are spared.

See also: [Original bugs](../rewrite/original-bugs.md) ·
[Perk runtime reference (RE)](../re/static/perks-runtime-reference.md)
