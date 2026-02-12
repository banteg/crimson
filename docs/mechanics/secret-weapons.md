---
tags:
  - mechanics
  - systems
  - secrets
---

# Secret weapons

Several weapons in Crimsonland are not unlocked through normal quest
progression. Three verified paths exist:

- One persistent progression unlock (Splitter Gun)
- Two Survival rewards (Shrinkifier 5k, Blade Gun)

For decompiler-level details, gate variables, and evidence pointers, see
[Survival weapon handouts (RE/static)](../re/static/secrets/survival-weapon-handouts.md).

## Splitter Gun

Every projectile that hits a creature splits into two child projectiles
diverging at 120 degrees. The children can split again on subsequent hits,
creating exponential chain reactions through clustered enemies. Each impact
throws off yellow-gold sparks. At 6x damage, every fragment hits hard enough
to matter.

Splitter Gun is a persistent unlock, not a temporary reward. It becomes
available after beating 4.10 *The End of All* on hardcore. Once unlocked it
appears in the normal weapon pool.

## Survival rewards

In single-player Survival, the game can grant hidden weapons under strict
conditions. These are temporary rewards that do not persist across runs.

### Shrinkifier 5k

Fires blue plasma bolts that deal no direct damage. Instead, each hit
shrinks the target to 65% of its current size. Once a creature shrinks
below size 16, it dies. A typical enemy takes about four or five hits to
collapse entirely, each shot visibly squeezing it smaller with a blue
pulse and scattered particle puffs.

In single-player Survival, survive for 64 seconds without taking damage
and without firing. When the timer check runs, you must still be holding
the Pistol. If you've picked up another weapon by then, the opportunity
is silently consumed and won't come back.

### Blade Gun

A slow, heavy-hitting piercing weapon. Each shot carries a damage pool of
50, meaning a single blade can cut through an entire line of enemies before
being spent. With an 11x damage multiplier, individual hits are devastating.
The projectile renders as a segmented beam rather than a ball, reinforcing
the cutting visual.

In single-player Survival, kill exactly three creatures, then walk to the
center of the triangle formed by those three deaths without firing. If
you're within distance 16 of that center and your health is below 15, the
game grants the Blade Gun. Unlike the Shrinkifier, this does not require being
damage-free or still on the Pistol. The third kill itself resets the fire
flag, which is what opens the path.

## Unverified weapons

17 named weapons exist in the weapon table but are absent from the quest
unlock sequence. Beyond the three listed above, no verified unlock path is
currently documented. See
[weapon candidates (RE/static)](../re/static/secrets/weapon-candidates.md)
for the full candidate list and analysis.
