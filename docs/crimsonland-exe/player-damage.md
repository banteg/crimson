---
tags:
  - status-analysis
---

# Player damage

`player_take_damage` (`0x00425e50`) takes a player index and float damage.
The recovered body is `tools/match/scratches/player_take_damage/scratch.cpp`;
Python implements it in `src/crimson/player_damage.py`.

Native code xrefs are `player_update` at `0x00415a03` (Ammunition Within) and
`creature_update_all` at `0x00427346` (contact damage). Death-only work, including
Final Revenge, executes synchronously at those callsites. Direct health writes
in projectile and perk code do not inherit this function's behavior.

## Gates and damage

Order matters for both state and RNG:

1. Death Clock returns immediately, before setting the Survival damage gate.
2. Tough Reloader halves damage while reloading.
3. Set `survival_reward_damage_seen`, then return if Shield is active. An immune
   shielded hit still consumes the damage-free Survival reward opportunity.
4. Snapshot whether **player 0** was dead. This native multiplayer quirk controls
   later early returns; see [original bugs](../rewrite/original-bugs.md).
5. Thick Skinned selects scale `0.666f`, otherwise `1.0f`.
6. Ninja dodges on `rand() % 3 == 0`. Only without Ninja does Dodger test
   `rand() % 5 == 0`.
7. If not dodged, Highlander writes health to exactly zero on `rand() % 10 == 0`
   and otherwise ignores the hit. Without Highlander, subtract `scale * damage`.

## Post-damage path

A dodge jumps to the shared post-damage path; it does **not** skip pain/death
handling or its RNG. Health strictly below zero decrements the death timer by
`frame_dt * 28`. The prior player-0 death snapshot can then return early.
Otherwise Final Revenge runs inline or a death sound is selected. Health at or
above zero takes the pain-sound branch, including Highlander's exact-zero result.
The wider game uses `health <= 0` to treat a player as dead.

If not dodged, Unstoppable suppresses the heading kick and spread increase.
Otherwise heading gains `(rand() % 100 - 50) * 0.04f`; spread gains
`damage * 0.01f`, capped at `0.48f` (using reload-mitigated damage before Thick
Skinned scaling). At health `<= 20`, `(rand() & 7) == 3` resets the low-health
warning timer to zero.

Creature contact is governed by `attack_cooldown`, with a `1.0` increment per
attack. The separate `collision_timer` governs creature infection/proximity
health effects. See [creature update](../creatures/update.md) and
[player layout](../structs/player.md).
