---
icon: lucide/heart
tags:
  - mechanics
  - combat
  - health
---

# Damage and death

This page documents how player health changes over time and how death is evaluated. It does not cover creature damage values.

## How player damage is taken

A player can lose health from:

- Creature contact damage.
- Projectile damage.
- Poison ticks from creature melee effects (`Veins of Poison`, `Toxic Avenger`).

The shield timer and `Death Clock` are hard gates that stop normal incoming damage checks.

## Contact damage

Contact damage is checked when a live creature is close enough to attack and the player is not protected by shield or the `Death Clock` immunity window.

If `Dodger` is active, each normal contact hit has a **1 in 5** dodge chance.

If `Ninja` is also active, use **1 in 3** dodge instead (Ninja takes precedence).

If the hit is not dodged:

- `Thick Skinned` reduces damage to **2/3**.
- `Tough Reloader` reduces damage to **1/2** while reloading.
- `Unstoppable` suppresses knockback and spread disruption from the hit.
- `Highlander`: even when the hit would normally deal damage, there is a **1 in 10** chance to die instantly.

## Projectile damage

Projectile hits use a fixed base of **10** damage.

These are still blocked by shield/`Death Clock`, but dodge checks are not the same branch as normal contact flow in the current implementation.

## Poison pressure on the player

When you are poisoned by creature contact:

- `Veins of Poison`: base poison damage over time.
- `Toxic Avenger`: stronger poison damage over time.

That damage is periodic and independent from normal contact rolls.

## Low-health warning

When health reaches **20 or below**, there is a **1 in 8** chance to trigger the low-health warning state.

Treat this as a high-priority warning and reset your spacing immediately.

## Self-damaging and lethal perks

Several perks affect player health directly and are part of the damage/death plan:

- `Thick Skinned` applies a two-thirds health drop on pick, then clamps to at least 1 HP.
- `Grim Deal` kills instantly on pick.
- `Fatal Lottery`: 50% instant death, 50% bonus XP.
- `Infernal Contract`: sets alive players to `0.1` health.
- `Breathing Room`: drops alive players to one-third health (`-2/3` health).
- `Jinxed`: every **2.0 to 3.9** seconds, **1 in 10** chance to lose **5** health.
- `Death Clock`: starts at 100 HP, then drains at **3.3333333 HP/s** for about 30 seconds.

## Death state and run transition

When health reaches zero:

- combat input and movement are no longer active in the normal play flow,
- death timers begin,
- and run/state transition waits until all dead players have passed their death timing checks.

In co-op, your run does not advance until every dead player has completed their own death timer window.
