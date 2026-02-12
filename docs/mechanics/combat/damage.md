---
icon: lucide/heart
tags:
  - mechanics
  - combat
  - health
---

# Damage and death

Your health bar is finite and fragile. Most damage follows a few predictable rules, so you can plan around it instead of guessing.

## How damage is dealt

You can take damage from:

- Creature contact.
- Projectile hits.
- Ongoing effects like poison and toxic auras.

Contact and creature effects are where most early deaths come from, because they bypass your firing rhythm and punish movement errors.

## Contact damage and touch effects

- Contact damage is checked while the creature is active and physically touching you.
- If poison is active (`Toxic Avenger` or `Veins of Poison`), it deals damage over time frame-by-frame in addition to contact hits.
- `Plaguebearer` and `Radioactive` add creature-related damage pressure around the player, so you can be under threat even without direct bullet exchange.
- While your shield timer is running, incoming damage is ignored.
- `Death Clock` makes incoming normal damage bypass your health as well.

## Projectile damage

Most creature- or enemy-fired shots that reach the player apply a fixed **10 damage** before modifiers.

There is a dedicated projectile damage path, so normal dodge checks that apply to some contact flows do not apply the same way to projectiles.

## Dodge odds and damage reduction

For a normal player hit, dodge checks are:

- `Ninja`: **1 in 3** chance to dodge the hit entirely.
- `Dodger`: **1 in 5** chance to dodge the hit entirely.

If both are present, the `Ninja` check is used first.

If the hit is not dodged:

- `Thick Skinned`: damage is multiplied by **about 2/3 (0.666)**.
- `Tough Reloader`: damage is multiplied by **0.5** while reloading.
- `Unstoppable`: removes knockback/aim disruption side effects from the hit.
- `Highlander`: after a surviving hit, there is a **1 in 10** chance to be killed instantly.

## What hurts aiming

A non-avoided hit also applies a small, temporary spread/jitter effect. It stacks with low-health danger, so the same incoming damage can feel much worse when your bar is already emptying.

## Low-health warning behavior

When your health is **20 or less**, the low-health warning can trigger with probability:

- **1 in 8** chance at trigger check.

Treat this as a red-light moment: leave open lines, break contact, and recover spacing.

## Death transition

Once health reaches zero:

- you are no longer able to shoot or move normally,
- and the game waits for the death-state timers before changing run state.

In co-op, the run-level transition only finishes when all dead players have completed their individual death timing windows.

## Death can still matter

`Final Revenge` can trigger when you die, and it can clear nearby threats instantly in a blast radius while you are downed.

## Quick facts

- `Ninja`: 1/3 dodge, `Dodger`: 1/5 dodge.
- `Thick Skinned`: ≈×0.666 damage (about 2/3).
- `Tough Reloader`: ×0.5 damage while reloading.
- `Highlander`: 1/10 instant-death chance on a non-fatal hit.
- Projectile base damage: 10.
- Shield and `Death Clock` are full-negation windows against damage.
