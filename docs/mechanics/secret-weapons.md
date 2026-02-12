---
icon: lucide/swords
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

Shrinkifier 5k and Blade Gun are temporary, granted under strict conditions
in single-player Survival and lost at the end of the run.

For decompiler-level details, gate variables, and evidence pointers, see
[Survival weapon handouts (RE/static)](../re/static/secrets/survival-weapon-handouts.md).

## Splitter Gun

Each shot that hits a creature spawns two child projectiles at +/-60 degrees
(120 degrees apart). Those children can split again on later hits, so dense
enemy packs can chain into rapid branching bursts. Each impact throws off
yellow-gold sparks. In the original game, Splitter fragments can also hit the
player, so bad angles can bounce damage back at you. At 6x damage, fragments
still hit hard enough to matter.

Splitter Gun is a persistent unlock, not a temporary reward. It becomes
available after beating 4.10 *The End of All* on hardcore. Once unlocked it
appears in the normal weapon pool.

## Shrinkifier 5k

Fires blue plasma bolts that shrink the target to 65% of its current size on
every hit while also applying a normal damage hit. If a creature shrinks below
size 16, it dies immediately. In practice, enemies usually collapse in a few
hits (often around three for medium-size targets), with visible blue pulse and
particle effects on impact.

In single-player Survival, survive for 64 seconds without taking damage
and without firing. When the timer check runs, you must still be holding
the Pistol. If you've picked up another weapon by then, the opportunity
is silently consumed and won't come back.

## Blade Gun

A piercing weapon with a very high damage scale (11x in weapon data). Each
shot starts with a pierce pool of 50, but that is not "50 creatures" - the
pool is consumed by damage interactions, so real pierce count varies by target
health and hit order. Visually, the projectile appears as a short slash-like
trail rather than a standard bullet orb.

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
