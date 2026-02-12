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
- Two hidden Survival rewards (Shrinkifier 5k, Blade Gun)

For decompiler-level details, gate variables, and evidence pointers, see
[Survival weapon handouts (RE/static)](../re/static/secrets/survival-weapon-handouts.md).

## Splitter Gun

Every projectile that hits a target splits into two child projectiles
diverging at 120 degrees. The children can split again on subsequent hits,
creating exponential chain reactions through clustered enemies. Each impact
throws off yellow-gold sparks. At 6x damage, every fragment hits hard enough
to matter.

Splitter Gun is a persistent unlock, not a temporary reward. It becomes
available after beating 4.10 *The End of All* on hardcore. Once unlocked it
appears in the normal weapon pool.

## Hidden Survival rewards

In single-player Survival, the game can grant hidden weapons under strict
conditions. These are temporary rewards — they do not persist across runs.

### Shrinkifier 5k

Fires blue plasma bolts that deal no direct damage. Instead, each hit
shrinks the target to 65% of its current size. Once a creature shrinks
below size 16, it dies. A typical enemy takes about four or five hits to
collapse entirely — each shot visibly squeezing it smaller with a blue
pulse and scattered particle puffs.

In single-player Survival, survive for 64 seconds without taking damage,
without firing, and without picking up another weapon, and the game
replaces your Pistol with the Shrinkifier. The check only fires once per
run — if the timer passes while you're holding a picked-up weapon instead
of the Pistol, the opportunity is silently consumed and won't come back.

### Blade Gun

A slow, heavy-hitting piercing weapon. Each shot carries a damage pool of
50, meaning a single blade can cut through an entire line of enemies before
being spent. With an 11x damage multiplier, individual hits are devastating.
The projectile renders as a segmented beam rather than a ball, reinforcing
the cutting visual.

Granted when the player returns to the centroid of their first three kill
positions under pressure. All of these must be true:

- single-player Survival
- exactly 3 creatures have died so far
- the player has not fired since the 3rd kill
- the player is within distance 16 of the average position of the first 3
  death locations
- the player's health is below 15

Unlike the Shrinkifier, this check does not require the player to be
damage-free or still on the Pistol, and it does not require the handout
system to be in its initial state. The 3rd creature death itself resets
the fire flag, which is what opens the Blade Gun path.

### Reward guard

Both weapons are guard-protected: each world step, if the player is holding
Shrinkifier 5k or Blade Gun without the matching guard, the game forces a
switch back to Pistol. The guard is set when the weapon is granted and reset
at the start of each run. This makes them effectively single-run rewards —
switching away or starting a new run loses them.

## Other non-quest weapons

17 named weapons exist in the weapon table but are absent from the quest
unlock sequence. Beyond the three listed above, no verified unlock path is
currently documented. See
[weapon candidates (RE/static)](../re/static/secrets/weapon-candidates.md)
for the full candidate list and analysis.
