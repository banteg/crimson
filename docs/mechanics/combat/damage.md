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
- Poison ticks from creature melee effects ([Veins of Poison](../perks.md#36-veins-of-poison), [Toxic Avenger](../perks.md#37-toxic-avenger)).

The shield timer and [Death Clock](../perks.md#47-death-clock) are hard gates that stop normal incoming damage checks.

## Contact damage

Contact damage is checked when a live creature is close enough to attack and the player is not protected by shield or the `Death Clock` immunity window.

If [Dodger](../perks.md#26-dodger) is active, each normal contact hit has a **1 in 5** dodge chance.

If [Ninja](../perks.md#40-ninja) is also active, use **1 in 3** dodge instead (Ninja takes precedence).

If the hit is not dodged:

- [Thick Skinned](../perks.md#33-thick-skinned) reduces damage to **2/3**.
- [Tough Reloader](../perks.md#56-tough-reloader) reduces damage to **1/2** while reloading.
- [Unstoppable](../perks.md#22-unstoppable) suppresses knockback and spread disruption from the hit.
- [Highlander](../perks.md#41-highlander): even when the hit would normally deal damage, there is a **1 in 10** chance to die instantly.

## Projectile damage

Projectile hits use a fixed base of **10** damage.

These are still blocked by shield/[Death Clock](../perks.md#47-death-clock), but dodge checks are not the same branch as normal contact flow in the current implementation.

## Poison pressure on the player

When you are poisoned by creature contact:

- [Veins of Poison](../perks.md#36-veins-of-poison): base poison damage over time.
- [Toxic Avenger](../perks.md#37-toxic-avenger): stronger poison damage over time.

That damage is periodic and independent from normal contact rolls.

## Low-health warning

When health reaches **20 or below**, there is a **1 in 8** chance to trigger the low-health warning state.

Treat this as a high-priority warning and reset your spacing immediately.

## Self-damaging and lethal perks

Several perks affect player health directly and are part of the damage/death plan:

- [Thick Skinned](../perks.md#33-thick-skinned) applies a two-thirds health drop on pick, then clamps to at least 1 HP.
- [Grim Deal](../perks.md#8-grim-deal) kills instantly on pick.
- [Fatal Lottery](../perks.md#15-fatal-lottery): 50% instant death, 50% bonus XP.
- [Infernal Contract](../perks.md#24-infernal-contract): sets alive players to `0.1` health.
- [Breathing Room](../perks.md#46-breathing-room): drops alive players to one-third health (`-2/3` health).
- [Jinxed](../perks.md#42-jinxed): every **2.0 to 3.9** seconds, **1 in 10** chance to lose **5** health.
- [Death Clock](../perks.md#47-death-clock): starts at 100 HP, then drains at **3.3333333 HP/s** for about 30 seconds.

## Death state and run transition

When health reaches zero:

- combat input and movement are no longer active in the normal play flow,
- death timers begin,
- and run/state transition waits until all dead players have passed their death timing checks.

In co-op, your run does not advance until every dead player has completed their own death timer window.
