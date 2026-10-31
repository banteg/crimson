---
tags:
  - rewrite
---

# Original bugs (rewrite)

The classic `crimsonland.exe` has a few behaviors that look like genuine bugs
once you read the decompile and trace their gameplay impact.

The gameplay fixes below apply **by default** where specified. For parity work
and future differential testing, you can re-enable those original behaviors with
`--preserve-bugs`. Original text quirks, the late-game Survival spawn rate, piercing damage-pool growth, the Shrinkifier's repeated death rewards and the Bubblegun's stale target are documented only and always preserved.

The historical [rules-2 candidate assessment](https://github.com/banteg/crimson/blob/1c710a97e997f924cc7d6a89aa1c7269fd9df516/docs/rewrite/original-bugs-triage.md)
remains in git history. This ledger records adopted behavior; entry 50 is an
explicit consistency/balance choice, not a proven original defect.

The ledger covers both builds a run can play: 1.9.93, the default, and 1.9.8
under the [1.9.8 rules](rules-1.9.8.md). Entries 1-55 describe 1.9.93; most
are shared with 1.9.8 and keep their treatment there, and a **1.9.8:** note
says where the older build differs. Entries 56-60 exist only in 1.9.8. Their
default plays as 1.9.93 does, and `--preserve-bugs` keeps 1.9.8's native
behavior. The 1.9.8 rules themselves (the additive Fire Bullets model, the
missing perks and the other changes listed on their page) are not bugs and
apply under both policies.

## 1) Bonus drop suppression: `amount == current weapon id`

Native behavior:

- In `bonus_try_spawn_on_kill` (`0x0041f8d0`), after spawning a bonus, the exe
  clears the spawned entry if either:
  - there’s already another bonus of the same `bonus_id` on the ground (duplicate
    suppression), or
  - `bonus.amount == player1.weapon_id` **regardless of bonus type**.

Why it’s likely a bug:

- For non-weapon bonuses, `amount` is usually the bonus metadata “default
  amount”, which lives in a different integer domain than weapon ids.
- This creates accidental “hard bans” where certain bonuses never drop while
  holding specific weapons, and it can also reduce the overall drop rate (the
  drop is canceled, not rerolled).

Examples of the accidental hard bans (native metadata):

- `Nuke` / `Double Experience` / `Shock Chain` / `Fireblast` (`amount=1`, the
  `bonus_meta_cpp_t` constructor default that `bonus_metadata_init` never
  overrides) while holding `Pistol` (`weapon_id=1`)
- `Reflex Boost` (`amount=3`) while holding `Shotgun` (`weapon_id=3`)
- `Fire Bullets` (`amount=4`) while holding `Sawed-off Shotgun` (`weapon_id=4`)
- `Freeze` (`amount=5`) while holding `Submachine Gun` (`weapon_id=5`)
- `Shield` (`amount=7`) while holding `Mean Minigun` (`weapon_id=7`)
- `Speed` / `Energizer` (`amount=8`) while holding `Flamethrower` (`weapon_id=8`)
- `Weapon Power Up` / `MediKit` (`amount=10`) while holding `Multi-Plasma` (`weapon_id=10`)

The check sits on the normal drop path only; the Pistol's forced Weapon drop
has its own checks. Evidence:
`decomp/1.9/crimsonland/crimsonland/bonus_try_spawn_on_kill.cpp` (the reject
after the 56-unit conversion), `gameplay/bonus_meta_entry_init.cpp` and
`gameplay/bonus_metadata_init.cpp`.

Rewrite behavior:

- Default: only suppress `Weapon` drops that match a currently carried weapon id
  (primary/alternate across co-op players).
- With `--preserve-bugs`: re-enable the exe’s `amount == weapon_id` suppression
  rule for all bonus types.

## 2) Greater Regeneration has no runtime effect

Native behavior:

- `perk_id_greater_regeneration` is defined and unlockable, but no gameplay tick
  logic reads it.
- `perks_update_effects` only checks `perk_id_regeneration`.
- `perk_apply` only touches Greater Regeneration indirectly via Death Clock
  clearing both regen perk counts.

Why it’s likely a bug:

- The in-game description says Greater Regeneration should replenish health
  “faster than ever.”
- It has a prerequisite (`Regeneration`), so the intended design is clearly an
  upgrade path, but the effect implementation is missing.

Rewrite behavior:

- Default: Greater Regeneration upgrades Regeneration heal ticks from `+dt` to
  `+2*dt` (same RNG gate/timing as base Regeneration).
- With `--preserve-bugs`: keep original behavior where Greater Regeneration is a
  no-op.

## 3) Bandage applies a health multiplier instead of a heal

Native behavior:

- `perk_apply` computes `roll = (crt_rand() % 50) + 1`.
- It multiplies each player's health by `roll`, then clamps to `100`. The loop
  has no alive check: dead players also consume a `crt_rand()` draw, have their
  (negative) health multiplied, and spawn a heal burst at the corpse.

Why it’s likely a bug:

- The perk text says it “restores up to 50% health.”
- A ×1..×50 multiplier is wildly different from a bounded heal and can jump from
  low health to full almost every time.

Rewrite behavior:

- Default: heal each alive player by `+1..+50` HP (1-50% of a 100-HP bar), then
  clamp to `100`.
- With `--preserve-bugs`: keep the original multiplier behavior.

## 4) Player-facing text quirks (documented, not fixed)

The original spelling, grammar, capitalization, punctuation, and abbreviated
labels are part of the game's character. The Python port displays the original
text in all modes, regardless of `--preserve-bugs`; there is no corrected-text mode.
This policy affects text only, not any of the gameplay fixes documented here.

Source evidence: `analysis/ghidra/raw/crimsonland.exe_strings.txt`.
The following inventory records the original wording for reference.

| Area | Original text (all modes) |
| --- | --- |
| Perk name | `Fire Caugh` |
| Weapon name | `Plague Sphreader Gun` |
| Weapon name | `Lighting Rifle` |
| Weapon name | `Fire bullets` |
| Perk description (`Anxious Loader`) | `waiting your gun to be reloaded` |
| Perk description (`Dodger`) | `attacks you you have a chance` |
| Perk description (`Ninja`) | `have really hard time` |
| Perk description (`Living Fortress`) | `It comes a time ... Being living fortress ... You do the more damage ...` |
| Bonus description (`Weapon Power Up`) | `Your firerate and load time increase for a short period.` |
| Bonus description (`Fire Bullets`) | `For few seconds -- make them count.` |
| End note line | `You've completed all the levels but the battle` |
| Quest failed line | `Persistence will be rewared.` |
| Tutorial hint | `Picking it you gets a new weapon.` |
| Tutorial hint | `exposion` |
| Weapon database panel label | `wepno #<id>` |
| Weapon database panel label | `Firerate` |
| Perk database panel label | `perkno #<id>` |
| Quest results prompt | `State your name trooper!` |
| Game over hit-ratio tooltip | `The % of shot bullets hit the target` |
| Statistics panel line | `played for 1 hours 1 minutes` |

**1.9.8:** shared, except that 1.9.8 has no Fire Cough or Living Fortress
(`perks_init_database`), so a 1.9.8 run never offers the perks behind the
`Fire Caugh` and `Living Fortress` rows above.

## 5) Stationary Reloader can finish a reload without refilling ammo

Native behavior:

- `player_update` preloads ammo when `reload_timer - frame_dt < 0` (unscaled `frame_dt`),
  then later applies Stationary Reloader by decrementing `reload_timer` using
  `reload_scale * frame_dt` (with `reload_scale = 3` when stationary).
- When Stationary Reloader is active, `reload_timer` can underflow in a single tick
  even though `reload_timer - frame_dt` was still non-negative. In that case ammo is
  never refilled when the reload completes.
- This can lead to a “one shot + forced reload loop” (reload completes with `ammo == 0`,
  the next shot underflows ammo and restarts reload).
- Independently of Stationary Reloader, the strict `< 0` preload test misses
  exact-zero completion. A Pulse Gun reload of 0.1 seconds at 50 FPS reaches
  zero after five ticks without refilling. The original executable's reload
  fragment and the Python port reproduce this with no perks.

Why it’s likely a bug:

- The intent is clearly “refill ammo when reload completes”; the underflow check
  just fails to account for the Stationary Reloader scale factor.

Rewrite behavior:

- Default: use the scaled reload decrement (`reload_scale * frame_dt`) and
  include equality (`timer - decrement <= 0`). Require a positive starting
  timer, so an idle gun does not refill every frame. Exact-zero completion is
  included starting with rules 2.
- With `--preserve-bugs`: keep the native unscaled, strict-negative preload
  check (and the empty-reload loop).

## 6) Weapon-drop proximity conversion checks player 1 only

Native behavior:

- In `bonus_try_spawn_on_kill` (`0x0041f8d0`), when the spawned bonus is
  `Weapon`, the 56-unit proximity check uses only `player1.pos`.
- In co-op, a weapon drop near only player 2 does **not** convert to a
  100-point bonus.

Why it’s likely a bug:

- The conversion mechanic is otherwise positional and player-agnostic.
- In co-op this creates asymmetric drop behavior based only on which player is
  index 0.

Rewrite behavior:

- Default: convert Weapon drops to 100-point bonuses when they spawn within
  56 units of **any** player.
- With `--preserve-bugs`: keep native player-1-only proximity conversion.

## 7) Regeneration applies to player 1 only in co-op

Native behavior:

- `perks_update_effects` checks `Regeneration` via player-1-owned perk state.
- On a regen tick, it updates only `player1.health`.
- In co-op, that same player-1 heal step is repeated `config_player_count` times.

Why it’s likely a bug:

- The perk text describes a player heal-over-time effect, and multiplayer systems
  otherwise operate on per-player health state.
- This creates asymmetric co-op behavior and over-heals player 1 as player count grows.

Rewrite behavior:

- Default: heal each alive player by `+dt` per triggered tick
  (or `+2*dt` with Greater Regeneration).
- With `--preserve-bugs`: keep native player-1-only, player-count-scaled ticks.

## 8) Co-op heart pulse speed inherits player 1 low-health state

Native behavior:

- In multiplayer HUD render (`hud_update_and_render`), player 1 pulse speed
  (`2.0` or `5.0`) is reused as the baseline for later heart icons.
- If player 1 is below 30 HP, player 2’s heart pulse runs at the “low health”
  speed even when player 2 is healthy.

Why it’s likely a bug:

- Health pulse speed should be per-player and tied to each player’s own health.
- This only affects presentation and creates asymmetric low-health cues in co-op.

Rewrite behavior:

- Default: pulse speed is computed per player from that player’s health.
- With `--preserve-bugs`: keep native coupling where player 1 low health forces
  low-health pulse speed for subsequent player heart icons.

## 9) Co-op damage/death SFX guard reads player 1 health

Native behavior:

- In `player_take_damage` (`0x00425e50`), the "was alive before this hit" guard
  is computed from `player1.health` even when damage is being applied to player 2.
- In co-op, if player 1 is already dead, player 2 damage can skip expected
  post-hit handling paths (pain/death SFX and related branches guarded by that
  pre-hit alive flag).

Why it’s likely a bug:

- The function otherwise applies damage and health checks to the indexed player.
- Reading player 1 health for this guard creates asymmetric co-op behavior that
  depends on unrelated player state.

Rewrite behavior:

- Default: compute the pre-hit alive guard from the target player's own health.
- With `--preserve-bugs`: keep native player-1-sourced guard behavior.

## 10) Jinxed random creature kill excludes slot 383

Native behavior:

- In `perks_update_effects` (`0x00406b40`), Jinxed chooses a random creature
  slot with `rand % 0x17f` (383), then retries up to 10 times if inactive.
- The creature pool has `0x180` (384) entries, so index `383` is never picked
  by the Jinxed kill roll.

Why it’s likely a bug:

- Other creature-slot random selection paths use the full 384-entry pool.
- The off-by-one modulo silently excludes one valid slot from the perk effect.

Rewrite behavior:

- Default: use the full `0x180` creature slot range for Jinxed random kills.
- With `--preserve-bugs`: keep native `% 0x17f` behavior.

## 11) Cursor-target perks read player 1 aim only in co-op

Native behavior:

- In `perks_update_effects` (`0x00406b40`), Doctor targeting, Pyrokinetic
  hit lookup, and Evil Eyes target selection all source aim from
  `player_state_table.aim_x/aim_y` (player 1) regardless of which player is
  alive/aiming.
- In co-op, if player 1 dies, these effects can keep using stale aim data and
  ignore surviving-player aim.

Why it’s likely a bug:

- These are cursor/aim-driven effects but are hard-wired to player 1 state.
- The behavior is asymmetric in co-op and can leave the surviving player unable
  to steer these perks as expected.

Rewrite behavior:

- Default: evaluate cursor-target perks per alive player, so Doctor/Pyrokinetic/
  Evil Eyes can use each player’s own aim in co-op.
- With `--preserve-bugs`: keep native player-1-only aim sourcing.

## 12) Jinxed self-damage always hits player 1 in co-op

Native behavior:

- In the Jinxed “accident” branch (`rand % 10 == 3`), `perks_update_effects`
  subtracts 5 HP from `player_state_table.health` directly.
- In co-op, the health penalty always applies to player 1.

Why it’s likely a bug:

- The perk downside is framed as self-harm, but the implementation is hard-wired
  to one player slot regardless of co-op state.
- This creates asymmetric risk where one player always pays the cost.

Rewrite behavior:

- Default: apply the 5 HP accident to a random alive player in co-op.
- With `--preserve-bugs`: keep native player-1-only self-damage.

## 13) Fire Bullets projectile override is globally coupled in co-op

Native behavior:

- In `projectile_spawn` (`0x00420440`), Fire Bullets conversion checks only
  whether player 1 or player 2 has an active Fire Bullets timer.
- The check is not owner-aware, so one player's timer can convert the other
  player's spawned projectiles.

Why it’s likely a bug:

- Fire Bullets timers are per-player in co-op.
- Global conversion couples projectile type to unrelated player state.

Rewrite behavior:

- Default: Fire Bullets conversion is owner-aware; spawned projectiles only
  convert when the firing player's timer is active.
- With `--preserve-bugs`: keep native player-1/player-2 global coupling.

**1.9.8:** different form, same coupling. 1.9.8's `projectile_spawn`
(`0x0041fc20`) keeps the shot and adds a Fire Bullets shot before it (the
recursive call at `0x0041fc91`), on either player's timer. In a 1.9.8 run the
default adds it only on the shooter's own timer, for any player's shot;
`--preserve-bugs` reads both timers and keeps the native owner list (`-100`
and `-1` to `-3`, so a fourth player's friendly-fire shots get none).

## 14) Pyromaniac offer gating checks player 1 weapon only in co-op

Native behavior:

- In `perks_generate_choices` (`0x004045a0`), when a random pick is
  `perk_id_pyromaniac`, the gate checks `player_state_table.weapon_id == 8`
  (Flamethrower).
- In co-op, this means Pyromaniac offerability depends on player 1 weapon only.

Why it’s likely a bug:

- Perk availability is shared in co-op, but the offer gate ignores other alive
  players’ current weapon state.
- This creates asymmetric offers where player 2 carrying Flamethrower does not
  unlock Pyromaniac unless player 1 also has it.

Rewrite behavior:

- Default: in co-op, allow Pyromaniac when any alive player has Flamethrower.
- With `--preserve-bugs`: keep native player-1-only weapon gating.

## 15) Joystick POV aim reads player 1 POV only in co-op

Native behavior:

- In `input_aim_pov_left_active` / `input_aim_pov_right_active`, POV input is
  read from joystick POV slot 0 only.
- In co-op, player 2 joystick aim can ignore player 2 POV input and instead
  respond to player 1 POV state.

Why it’s likely a bug:

- Joystick aim is evaluated per player, but the POV read is hard-wired to one
  slot.
- This creates direct input asymmetry in co-op.

Rewrite behavior:

- Default: read POV input from the current player's input slot.
- With `--preserve-bugs`: keep native slot-0 POV sourcing.

## 16) Pistol no-magnet fallback gate checks player 1 only in co-op

Native behavior:

- In `bonus_try_spawn_on_kill` (`0x0041f8d0`), when the base 1-in-9 spawn roll
  fails, the extra pistol fallback (`rand % 5 == 1`) is gated by player 1
  holding Pistol.
- In co-op, player 2 holding Pistol does not enable this fallback unless player
  1 also has Pistol.

Why it’s likely a bug:

- The earlier pistol safety-net path already scans all players.
- Using player-1-only state in the fallback path creates inconsistent,
  asymmetric co-op drop behavior.

Rewrite behavior:

- Default: allow the pistol fallback when any player currently holds Pistol.
- With `--preserve-bugs`: keep native player-1-only fallback gating.

## 17) Mini-Rocket Swarmers spread can collapse into clumped rockets

Native behavior:

- In `typo_player_update` (`0x00416a50`), Mini-Rocket Swarmers set per-rocket
  spread step to `ammo * 1.0471976` (`ammo * pi/3`), then spawn `ammo` rockets
  at `angle += step`.
- Because heading is periodic (`2*pi`), some clip sizes alias to repeated
  directions. Example: with clip size `6`, all six rockets get the same heading.

Why it’s likely a bug:

- Swarmers are intended to fire a spread burst, but clip-size modifiers can
  collapse multiple rockets onto identical trajectories.
- This makes some bursts look like a single projectile and reduces effective
  area coverage.

Rewrite behavior:

- Default: Mini-Rocket Swarmers use an even, aim-centered cone spread so each
  rocket in the burst gets a distinct heading.
- With `--preserve-bugs`: keep native ammo-scaled stepping (including clumping).

## 18) Exact-zero lethal hits skip death-only handling

Native behavior:

- In `player_take_damage` (`0x00425e50`), Highlander can set player health to
  exactly `0.0`.
- The function then routes `health >= 0.0` through the pain branch, while the
  death-only branch runs only when health drops below `0.0`.
- Exact-zero lethal hits therefore miss the immediate death-only work in that
  function: death SFX, Final Revenge, and the `death_timer -= frame_dt * 28.0`
  kick.

Why it’s likely a bug:

- Elsewhere in the exe, `health <= 0.0` counts as dead for player death state
  and game-over flow.
- Highlander itself creates the exact-zero case, so the split between
  “globally dead” and “not dead enough for death handling” looks accidental.

Rewrite behavior:

- Default: treat `health <= 0.0` as lethal for the `player_take_damage`
  death-only branch, so exact-zero kills trigger the same immediate handling as
  negative-health kills.
- With `--preserve-bugs`: keep native exact-zero behavior where Highlander kills
  fall through the pain branch.

## 19) Co-op auto-target replacement reuses mismatched player distances

Native behavior:

- In `creature_update_all` (`0x00426220`), once a creature picks its
  `target_player`, the auto-target replacement check compares the new creature’s
  distance against the current auto-target distance.
- In two-player mode, the new-creature side reuses the distance to the player
  opposite the creature's target at the start of reevaluation. If that player
  was farther and no retarget occurred, the comparison still uses that farther
  distance rather than the selected player's distance.
- The current auto-target side is always measured from
  `player_state_table.pos_x/pos_y` (player 1), even when the result is written
  back to `player2.auto_target`.
- The auto-target write also precedes dead-target redirection, so a dead
  player's slot can be updated immediately before the creature switches to the
  other player.
- If the opposite player is dead, native leaves the candidate-distance stack
  local untouched and compares whatever residue is present. Its first-use value
  is not recoverable from game state.

Why it’s likely a bug:

- The compare combines distances sourced from different players while the
  write is indexed to the selected target player.
- In co-op this can leave either player stuck on a worse auto-target, and it can
  update the dead player's slot during redirection.

Rewrite behavior:

- Default: compare both the new creature and the current auto-target against the
  final targeted player’s own position.
- With `--preserve-bugs`: keep the native opposite-player candidate distance,
  player-1-sourced current distance, and pre-redirection write order whenever
  the candidate local has an evidenced value. The undefined first-use residue
  case falls back deterministically to the selected player's distance.

## 20) No-target homing lookups silently fall back to creature slot 0

Native behavior:

- `creature_find_nearest` (`0x00420040`) initializes its return slot to `0` and
  never emits a “not found” sentinel.
- If no creature qualifies, the helper returns `0`, and its callers immediately
  treat that as a valid target.
- This affects Shock Chain startup/retargeting and seeker rocket
  spawn/retargeting when a frame has no valid target.

Why it’s likely a bug:

- The helper is clearly doing a nearest-target search, but a miss is silently
  converted into an unrelated pool index.
- This can point homing behavior at stale slot-0 data instead of ending the
  chain / rocket retarget cleanly.

Rewrite behavior:

- Default: use a no-target sentinel when no qualifying creature exists, so Shock
  Chain and seeker rockets stop retargeting instead of reusing slot 0.
- With `--preserve-bugs`: keep native slot-0 fallback behavior on target-search
  misses.

## 21) Trooper death SFX bank leaves slot 3 uninitialized

Native behavior:

- `audio_init_sfx` (`0x0043caa0`) loads only `trooper_die_01..03`; it does not
  load `trooper_die_04.ogg`.
- `gameplay_reset_state` (`0x00412dc0`) assigns trooper
  `creature_type_table[5].death_sfx[0..2]` only.
- `creature_apply_damage` (`0x004207c0`) still resolves trooper death audio with
  `death_sfx[rand & 3]`.
- Because the fourth slot is never written and the table lives in zero-initialized
  global storage, the native cold-start value is SFX id `0`
  (`sfx_trooper_inpain_01`).

Why it’s likely a bug:

- Every other shipped creature death bank is fully initialized with death sounds.
- `trooper_die_04.ogg` exists in `sfx.paq`, which strongly suggests the intended
  behavior was a fourth trooper death variant, not a 25% chance to play a pain
  grunt on death.

Rewrite behavior:

- Default: trooper deaths choose uniformly from the three loaded trooper death
  sounds.
- With `--preserve-bugs`: keep the native fourth-slot bug, so a trooper death
  roll of `3` resolves to `sfx_trooper_inpain_01`.

## 22) The Killing wave picks roll rand but branch on the wave counter

Native behavior:

- `quest_build_the_killing` (`0x4384a0`) calls `crt_rand()` twice per wave but
  discards both results, selecting the creature template with `wave % 3` and
  the spawn edge with `wave % 5`.
- The quest layout is therefore a fixed cycle (right/left/bottom/top/random
  spawners), with the random-spawner batches always on waves 4 and 9; only the
  spawner coordinates use real rolls.
- Capture evidence: in the 2026-06-13 quest 3.3 run, wave 9 rolled a layout
  value of 2 yet still spawned the random batch.

Why it's likely a bug:

- The discarded rolls strongly suggest the intent was `rand() % 3` and
  `rand() % 5`; the rng stream still advances two draws per wave for nothing.

Rewrite behavior:

- The rewrite mirrors the native behavior exactly (burn the rolls, branch on
  the wave index) so quest builds stay rng-stream aligned with the native quest builders.

## 23) Plaguebearer contact immunity activates player 1 only in co-op

Native behavior:

- In `perk_apply` (`0x004055e0`), acquiring Plaguebearer writes only
  `player_plaguebearer_active[0]`.
- Creature contact checks each colliding player's own flag, so player 2 never
  gains the contact-infection behavior from the shared perk in co-op.

Why it's likely a bug:

- Perk counts are shared across local players, and other immediate perk effects
  deliberately iterate over the configured player count.
- Applying the shared perk to only one player's contact flag creates asymmetric
  co-op behavior with no corresponding player-facing rule.

Rewrite behavior:

- Default: activate Plaguebearer contact infection for every player.
- With `--preserve-bugs`: keep native player-1-only flag activation.

## 24) Holding G while firing grants free Fire Bullets

**Observed original behavior:**

- `player_update` (`0x004136b0`) queries the fixed DirectInput G scan code
  (`0x22`) after the firing readiness/input gates and reload-bypass perk costs,
  casing effects, and shot jitter. A true result writes `10.0f` to the current
  player's Fire Bullets timer at `0x00415cf2`.
- The triggering shot already uses Fire Bullets. Subsequent eligible shots
  while G remains held assign ten seconds again, even reducing a longer timer.
- G alone, a blocked shot, death, and an open console do not grant the bonus.
  Computer auto-fire and reload-bypass perks can reach the shortcut.
- There is no developer-mode or console-cheat check on this path in the supplied
  `1.9.93-gog` executable. It appears to be a leftover cheat hook; its original
  developer intent is unknown.

**Rewrite policy:**

- Default: ignore this shortcut, including flags injected through replay input.
- `--preserve-bugs`: reproduce the ten-second grant on eligible shots. Ordinary
  Fire Bullets bonus pickups continue to work in both modes.
- Input recording stores the held G state in CRD/CDT bit 17. It is a held input,
  so fixed-step catch-up retains it; it is not a press edge or a configurable
  bonus action. Python enforces the policy in the firing routine.

**1.9.8:** absent. Neither 1.9.8's nor 1.9.9's `player_update` queries the G
scan code; among recovered builds it first appears in 1.9.92. A 1.9.8 run
ignores G and bit 17 under both policies.

Evidence: [player-fire-bullets-shortcut-2026-09-11](https://github.com/banteg/crimson/blob/8407308af2dcb1c1c15352f39f76b0cbfea900f3/tools/match/evidence/player-fire-bullets-shortcut-2026-09-11/README.md)
and the [Fire Bullets version comparison](../re/static/fire-bullets-1.9.8-vs-1.9.93.md).

## 25) Re-picking a bonus can leave its HUD indicator hidden for seconds

Native behavior:

- `bonus_apply` (`0x00409890`) activates a HUD slot only when the bonus timer is
  already zero. `bonus_hud_slot_activate` (`0x0041a810`) takes the first free
  slot, then deactivates every later slot that shares a timer pointer.
- Active slots always form a prefix of the table, so a re-pickup keeps the old
  slot and drops the new one. The old panel reverses from its current position.
- In `bonus_hud_slot_update_and_render` (`0x0041a8b0`), an expired slot is
  released only after every later slot is inactive. Until then it stays parked
  off-screen, and its X offset keeps falling by 320 px per second.
- Re-picking a parked bonus reverses from that position at 350 px per second.
  After five seconds parked, the indicator stays invisible for about 4.6 seconds.
  During that time the timer is running.

Why it's likely a bug:

- The slide animation assumes the offset never falls far past -184. There is no
  clamp for parked slots, so the time before the panel reappears grows with how
  long the slot was parked.

Rewrite behavior:

- Default: a parked slot stops just past the hidden edge, so a re-picked bonus
  slides back in right away. It only affects HUD presentation.
- `--preserve-bugs`: parked slots keep drifting left as in the original.

## 26) Bonus HUD dedupe scans one slot past the table (latent)

Native behavior:

- The dedupe loop in `bonus_hud_slot_activate` (`0x0041a810`) starts at
  `check_index = 16` in a 16-slot table. Slot 16 lies at
  `bonus_hud_slot_table + 0x200`, which is `quest_stage_label_buffer`
  (`0x0048f788`, `char[16]`).
- The loop compares label bytes 12–15 with each active slot's timer pointer.
  On a match it would write zero to the first label byte.

Why it has no effect:

- The label is a short string with zero padding, and active slots always hold a
  non-null timer pointer, so the comparison never matches.

Rewrite behavior:

- Documented only. The ports do not model the out-of-bounds slot.

Evidence: the exact `bonus_hud_slot_activate` scratch
(`tools/match/scratches/bonus_hud_slot_activate/`) and the native `.data` layout
in `analysis/native/crimsonland.exe/data.json`.

## 27) Enemy projectiles hurt through Death Clock

Native behavior:

- `player_take_damage` (`0x00425e50`) returns before any damage while Death
  Clock is active, so contact damage and other hits are ignored.
- `projectile_update` does not call it for enemy projectile hits. It subtracts
  10 health directly and only checks the shield, so Plasma Shooter and similar
  shots still land during the 30-second clock.

Why it's likely a bug:

- The perk promises that nothing else can harm the player while the clock runs
  down; ranged enemies are the one exception, with no apparent intent behind it.

Rewrite behavior:

- Default: enemy projectile hits are ignored while Death Clock is active.
- `--preserve-bugs`: they subtract 10 health as in the original.

Evidence: `decomp/1.9/crimsonland/crimsonland/projectile_update.cpp` (player hit
branch) and `decomp/1.9/crimsonland/crimsonland/player_take_damage.cpp`.

## 28) Bullet heads and plasma cores are never visible

Native behavior:

- `projectile_render` ends with a pass meant to draw a small `bullet_i` sprite at
  the head of every in-flight projectile (6 px for the pistol, 8 px for type 4,
  4 px otherwise), skipping Plasma Rifle, Plasma Minigun and Pulse Gun.
- The pass before it, the Fire Bullets glow, selects particle frame 13 with
  `effect_select_texture(13)`. The bullet pass binds `bullet_i` without resetting
  the UVs, so every quad samples the top-right quarter of the 16x16 texture,
  which is fully transparent.
- In game, bullets show only their trails, and plasma shots only their glow.
  At most a filtered edge texel can flicker near a spawning shot.

Why it's likely a bug:

- The heads used to show. In the freeware builds (1.0.2, 1.3.0, 1.3.1 and
  1.4.0) the last UV change before the pass is a `grim_set_uv(0, 0, 1, 1)` in
  an earlier pass, so every head drew the whole brass slug
  (`bullet_real_16.tga`, the same image as the later `bullet16.tga`), as
  freeware captures show. From 1.8.7 on, the glow pass right before it selects
  frame 13, and the heads vanish in every later build.
- Every shipped `grim.dll` binds a texture without touching the UVs, so only
  `crimsonland.exe` changed.
- The skip list never grew with the glowing and sprite shots. With the heads
  hidden, nothing showed a slug inside a Fire Bullets streak, an ion beam or a
  plasma glow.

Rewrite behavior:

- Default: the pass samples the whole sprite. It also skips Ion Rifle, Ion
  Minigun, Ion Cannon, Shrinkifier, Blade Gun, Spider Plasma, Plasma Cannon,
  Splitter Gun, Plague Spreader and Fire Bullets, so heads show on bullets and
  pellets only.
- `--preserve-bugs`: the pass samples the same texels as native, so no head shows.

Evidence: `decomp/1.9/crimsonland/crimsonland/projectile_render.cpp` (Fire Bullets
glow and late bullet pass), `effect_select_texture`, the head passes of every
build in `game_bins/crimsonland/`, captures of 1.9.93 on Windows (no heads,
Plasma Shooter spiders included) and of freeware 1.4.0 (heads). Executable-backed coverage is in
`tests/native_oracle/test_projectile_render.py`; the original texture's invisible
sampled corner is also checked on the GPU in
`tests/render/test_late_bullet_pass.py`.

## 29) A stray click picks a row from an open list

Native behavior:

- `ui_list_widget_update` closes an open list only when it is neither hovered nor
  focused, and hovering the open list gives it the keyboard focus. Focus moves only
  on Tab or when another focusable widget is hovered, so a list stays open after
  the mouse leaves it onto empty space.
- While open, the widget returns its `active_index`, the row last hovered. Callers
  toggle the list on any press when the result is `> -2` and take a row when it is
  `>= 0`, so the next click anywhere closes the list and selects that row.
- On the high-score screen this can silently switch the game mode, player count,
  date filter or score list with a click meant for empty space.

Rewrite behavior:

- Default: a click outside an open list closes it without taking a row. Clicking a
  row, the header, or pressing Enter on the focused list work as before.
- `--preserve-bugs`: the stray click takes the last hovered row, as native.

Evidence: `decomp/1.9/crimsonland/ui_widgets/ui_list_widget_update.cpp` and its
callers in `highscore_screen.cpp`, `controls_menu_update.cpp` and
`play_game_menu_update.cpp`.

## 30) Typ-o shot counts carry over from earlier runs

Native behavior:

- `typo_gameplay_update_and_render` counts Enter presses in `typo_submit_count`
  and name matches in `typo_match_count`, and copies both into the score
  record's shots fired and shots hit every frame.
- Nothing ever resets the two counters, so every Typ-o run after the first in a
  game session reports the words typed in all earlier runs too.

Rewrite behavior:

- The counters carry over like native (replays record them in `typo_carry`).
- Default: a run's score record counts only that run's words.
- `--preserve-bugs`: the record reports the running totals, as native.

Evidence: `decomp/1.9/crimsonland/typo/typo_gameplay_update_and_render.cpp`;
the only references to `typo_submit_count` and `typo_match_count` in
`crimsonland.exe` are in that function.

## 31) A resting aim stick swings the aim onto the player

Native behavior:

- Under Dual Action Pad aim, `player_update` (`0x004152f8..0x004153ba`) puts the
  aim point at the normalized aim stick times `min(|stick|, 1) *
  cv_padAimDistMul + 42`, from the position movement just produced. Unlike pad
  movement, which ignores a stick inside radius 0.2, the aim stick has no
  deadzone.
- A centred stick normalizes to zero, so the aim point lands on the player and
  the heading falls back to `fpatan(+0, +0) - pi/2`: letting go of the stick
  swings the weapon to face left.
- Any drift of a resting stick aims 42 units out in the drift's direction, so a
  worn stick makes the aim twitch.

Why it’s likely a bug:

- Every other aim scheme keeps its last direction when its input stops.
- The movement stick right next to it gets a deadzone.

Rewrite behavior:

- Default: inside stick radius 0.2 the aim keeps its last direction, 60 units
  from the player.
- `--preserve-bugs`: no deadzone, as native.

Evidence: `decomp/1.9/crimsonland/gameplay/player_update_heading.cpp` (aim
scheme 4) and the pad movement deadzone in the same function.

## 32) Projectile slot 0 cannot hit the player at first

Native behavior:

- `projectile_update` skips the player hit test for the projectile in slot
  `shock_chain_projectile_id`, the Shock Chain's current link.
- That global starts at 0 in a fresh game and is only set back to -1 when a
  chain ends. Nothing resets it at run start.
- So until the first Shock Chain of the game session ends, an enemy projectile
  that lands in slot 0 passes through the player.

Why it's likely a bug:

- The skip exists to keep the chain's own link from hitting players; the
  starting value makes it apply to an arbitrary enemy shot instead.

Rewrite behavior:

- Every run starts like a freshly launched game.
- Default: no projectile is skipped until a Shock Chain starts.
- `--preserve-bugs`: slot 0 is skipped as in a fresh original session.

Evidence: `decomp/1.9/crimsonland/crimsonland/projectile_update.cpp` (player hit
branch and the chain's end); `shock_chain_projectile_id` (`0x00486fc0`) has no
initializer in `crimsonland.exe`.

## 33) A bonus carrier can drop its bonus twice

Native behavior:

- `creature_handle_death` (`0x0041e910`) spawns a carrier's bonus whenever the
  creature has `CREATURE_FLAG_BONUS_ON_DEATH`, and never clears the flag.
- Some deaths are handled twice, for example by a secondary projectile's
  detonation follow-up on a creature that is already inactive, and the second
  call drops the bonus again.

Why it's likely a bug:

- A carrier holds one bonus; dropping a copy depends on how its death happened.

Rewrite behavior:

- Default: the carrier drops its bonus once.
- `--preserve-bugs`: every handled death drops it, as native.

Evidence: `decomp/1.9/crimsonland/crimsonland/creature_handle_death.cpp` (the
bonus spawn at the top) and `creature_spawn_template` (the only template that
sets the flag).


## 34) The Fire Bullets glow follows the last projectile slot

Native behavior:

- `projectile_render`'s Fire Bullets glow loop tests
  `projectile->type_id`, a pointer the sprite pass leaves on the last pool slot
  (95), instead of the projectile it is drawing.
- So while slot 95 holds a Fire Bullets type, every projectile in flight gets
  the 64 px glow, pistol and ion shots included. The slot keeps its type after
  the shot ends, so the glow stays until another type takes the slot.
- Otherwise no projectile glows, Fire Bullets shots included. Spawns take the
  first free slot, so slot 95 fills only when the pool is full.

Why it's likely a bug:

- The loop draws at each projectile's own position and angle; only the type
  test reads another slot, through a pointer left over from an earlier loop.

Rewrite behavior:

- Default: each Fire Bullets shot in flight gets the glow, and nothing else does.
- `--preserve-bugs`: the glow follows slot 95, as native.

Evidence: `decomp/1.9/crimsonland/crimsonland/projectile_render.cpp` (the glow
loop after the Plague Spreader pass). Executable-backed coverage is in
`tests/native_oracle/test_projectile_render.py`.

**1.9.8:** shared, with the same treatment; the last slot is 63 in its 64-slot
pool.

## 35) Rocket detonation flashes draw the whole particle atlas

Native behavior:

- `bonus_render` draws each detonation's two orange flashes (64 and 200 units
  at full scale) after the particle pool, with `particles` still bound.
- Before them it calls `grim_set_uv(0, 0, 1, 1)`, so each flash stretches the
  entire particle atlas, debris, blood, explosion and ring cells included,
  rather than one glow cell.
- The atlas's ring cell sits in its bottom-right quarter, so a thin ring grows
  down-right of each blast, with small debris blobs up-left.

Why it's likely a bug:

- In 1.4.0 the flash binds the standalone `glow` texture (`glow64.tga`, one
  64x64 soft glow) by name before the same `grim_set_uv(0, 0, 1, 1)`, so the
  whole texture is the glow.
- By 1.8.7 the loose effect textures had moved into the `game\particles.jaz`
  atlas. The flash lost its own bind and kept the full-texture UVs, so it took
  the whole atlas the particle pass left bound, as 1.9.93 still does.
- The same move hid the bullet heads in
  [28)](#28-bullet-heads-and-plasma-cores-are-never-visible), in the opposite
  direction.
- The atlas keeps `glow64.tga` as 4x4 frame 6 (effect `0x10`), pixel for pixel.
  The ring is a separate cell (effect `0x01`); freeware drew its own
  `shockwave.tga` in other passes, not in this flash.

Rewrite behavior:

- Default: the flashes draw the soft glow cell, as freeware did.
- `--preserve-bugs`: they stretch the whole atlas, as native.

Evidence: `decomp/1.9/crimsonland/crimsonland/bonus_render.cpp` (the detonation
loop), the detonation flashes of the 1.4.0 and 1.8.7 builds in
`game_bins/crimsonland/`, captures of 1.9.93 on Windows showing the atlas in the
flash, and `tests/native_oracle/test_projectile_render.py`.

## 36) Ion chain arcs end in a hard cut

Native behavior:

- After an ion shot hits, `projectile_render` draws two strips from it to each
  creature in reach (half-widths 10 and 14 times the weapon's effect scale), then
  the ion glow on that creature at 32 times the scale.
- Each strip maps the glow's centre column across its width, so the full glow
  profile runs unchanged to the creature's centre and stops in a straight cut.
- The creature glow is narrower than the strips and half their combined
  brightness, so the cut shows across the creature, worst on the Ion Cannon.

Why it's likely a bug:

- The strips and the creature glow are cut from the same round glow, which
  suggests a soft arc that fades out at the creature.

Rewrite behavior:

- Default: each strip gets end caps cut from the glow's halves, one
  half-width long, so the arc closes in a round, seamless end.
- `--preserve-bugs`: the strips stop in a straight cut, as native.

Evidence: `decomp/1.9/crimsonland/crimsonland/projectile_render.cpp` (the
`creature_find_in_radius` loop) and `tests/native_oracle/test_projectile_render.py`.


## 37) Survival spawning grows without bound after fifteen minutes

Native behavior:

- `survival_update` (`0x00407cd0`) starts each wave with
  `interval = 500 - run_elapsed_ms / 1800`, using integer division.
- At 15:00 the interval reaches zero. At 15:01.800 it becomes negative.
  For each negative interval the inner loop spawns a creature and adds 2,
  then clamps the remaining interval to at least 1 ms. The outer loop keeps
  spawning until it catches up with `frame_dt_ms * config_player_count`.
- With a zero starting cooldown and one player, a 16 ms update at 30:00
  attempts 4,016 spawns. At 35:54.555 it attempts 5,584. Slow-motion bonuses
  change the game's elapsed-time increment and therefore the work per tick.
- Each attempt scans the 384 creature slots from zero. When all are occupied,
  `creature_alloc_slot` (`0x00428140`) returns slot 384, the constructed
  overflow slot. `survival_spawn_creature` (`0x00407510`) still draws its
  random values and writes that slot, even though it creates no usable enemy.

Why it's likely a bug:

- Spawn demand grows indefinitely despite the fixed-size pool. A saturated
  pool repeatedly incurs a complete scan and initializes the same overflow
  creature, thousands of times per tick. This also slows live simulation;
  preparing a replay amplifies it by running the whole recording at once.
- Profiling [this 35:54.555 recording](https://crimson.land/play/?watch=209b0cdb6d9345e8c2dc4eaeac654e929338eecf07aaad28aaf9137dd9bc38d6)
  counted 219,862,950 Survival spawn attempts over 210,268 input ticks.
  Browser preparation took 102.07 s on an Apple M1 Pro; sampled allocator
  self time was 35.67 s. These are host-specific measurements.

Rewrite behavior:

- Both bug policies preserve the spawn rate, RNG consumption and overflow
  writes. Clamping the rate or dropping failed spawns would change recorded
  runs, including subsequent random outcomes.
- The recovered C/C++ core, game and Python rewrite apply a behavior-preserving optimization:
  a local cursor resumes the first-free search within a wave batch. This batch
  only fills slots, so the first free slot cannot move backwards. Once the
  cursor reaches 384, later attempts perform no pool scan, while retaining
  the original full-pool logging and spawn body. Each update starts from zero;
  other allocation callers retain their original search.
- With the pool full, the core and game also skip a batch's overflow-slot
  rewrites before its last attempt: those attempts take only their random
  draws, and a type 3 among them keeps the slot's 0x80 flag. The 54-minute
  bot run on the board verifies 2.5 times faster.
- Python uses the same update-local cursor through `CreaturePool.alloc_slot`.
  Successful allocations still update generation and allocation/spawn counters.
  Within a Survival wave batch, a failed allocation takes only its random draws
  when a later spawn will overwrite the phantom; standalone spawns write it whole.

Evidence: the recovered `survival_update`, `survival_spawn_creature` and
`creature_alloc_slot` bodies, and
[`spawn_batch.py`](../../crimson-core/checks/spawn_batch.py), which executes
those late-game cases in the original x86 executable and compares optimized
batches against unoptimized recovered bodies. The
[optimization notes](https://github.com/banteg/crimson/blob/master/crimson-core/optimizations/README.md)
describe how to measure them.

## 38) Quest difficulty leaks into Survival and the Tutorial

Native behavior:

- `config_blob.hardcore` is a saved setting, ticked from the quest list. It is
  cleared only while quest 4.10 is unbeaten, by `game_frame_update`
  (`0x0040c1c0`), in the demo build, and by the quest list and high-score
  screens under the same condition. Starting another mode leaves it set.
- `quest_fail_retry_count` counts a failed quest's **Play Again** presses.
  The quest failed screen's other buttons, the quest results screen and
  hardcore spawns clear it. Quitting a retried quest from the pause menu
  leaves it set.
- `creature_spawn_template` (`0x00430af0`) reads both for every creature it
  builds. Survival's milestone waves (`survival_update`, `0x00407cd0`) and
  the Tutorial's creatures (`tutorial_timeline_update`, `0x00408990`) come
  from the same templates, so they get either the hardcore buffs (20% more
  health after their maximum is set, 5% more speed, 40% more contact damage,
  nests 0.2 s faster, the stop-and-go yellow spiders at 70% speed) or the
  retry easing (down to half health and contact damage, 60% speed, 80% XP,
  nests up to 3 s slower), in most formations only on the last member.
- Survival's regular spawns read neither.

Why it's likely a bug:

- Both are quest settings: the Hardcore box sits on the quest list, quests
  keep separate hardcore progress and score tables, and quest builders add
  their own hardcore extras. The retry easing answers a failed quest, and
  the failed screen's own buttons clear it.
- Survival keeps a single score table, `survival.hi`, so tougher, easier and
  normal runs rank against each other. `highscore_record_init` marks the
  record as hardcore, but nothing reads that marker outside quests.

Rewrite behavior:

- Default: Hardcore and the retry easing apply to quests only. Replays still
  record the saved box and the retry count, as the original's runs carry
  them.
- `--preserve-bugs`: both also apply to Survival and the Tutorial, as native.

Evidence: `decomp/1.9/crimsonland/quests/creature_spawn_template.cpp` (the
hardcore and retry reads after the spawn switch), `game/game_frame_update.cpp`
(the hardcore clears), `end_screens/quest_failed_screen_update.cpp` and
`end_screens/quest_results_screen_update.cpp` (the retry count),
`game/survival_update.cpp`, `game/tutorial_timeline_update.cpp` and
`highscore/highscore_record_init.cpp`.

## 39) Blood splatters and corpse shatters exhaust the 511-slot effect pool

Native behavior:

- `effect_pool` (`0x004ab270`) holds 512 entries, linked as `0 -> 1 -> ... -> 511`
  by `effect_defaults_reset` (`0x0042df10`). Slot 511 is the sentinel whose
  `next_free` is null; when `effect_free_list_head` reaches it, `effect_spawn`
  (`0x0042e120`) writes into `effect_discard_entry` instead of allocating a
  live particle.
- Two paths flood the pool in busy Survival scenes:
  - Piercing projectiles (`PROJECTILE_TYPE_FIRE_BULLETS`,
    `PROJECTILE_TYPE_GAUSS_GUN`, `PROJECTILE_TYPE_BLADE_GUN`) step in 4-pixel
    microsteps (`projectile_update`, `0x00420b90`), and `creature_find_in_radius`
    (`0x004206a0`) matches dying corpses while `death_timer > 5.0f` (~0.55 s).
    Because `damage_pool` is only decremented when `creature_pool[hit_id].health > 0.0f`,
    a piercing shot hits each dying corpse on every 4-pixel microstep without
    losing `damage_pool`. With Bloody Mess, each microstep hit spawns 9
    `effect_spawn_blood_splatter` calls (`18` `effect_id = 7` particles),
    filling all 511 slots with blood.
  - Picking up `BONUS_ID_FREEZE` (`bonus_apply`, `0x004098f0`) loops over all
    384 creature slots and shatters every corpse (`active && health <= 0.0f`)
    into 8 `effect_spawn_freeze_shard`s and 1 `effect_spawn_freeze_shatter`
    (`16` particles per corpse) before spawning the Freeze pickup ring
    (`effect_spawn(1, ...)`) at the end of the branch. With 32 or more corpses
    on screen, the shatter loop fills all 511 slots before the pickup ring
    runs, even without Bloody Mess.
- While the pool is full, subsequent non-blood effects—Reflex Boost and Freeze
  pickup rings (`effect_id = 1`), Ion/Plasma/Shrinkifier/Explosion cores and
  sparks (`0`, `1`, `12`, `17`), freeze shatters and shards (`8..10`, `14`) and
  shell casings (`18`)—are discarded.

Why it's likely a bug:

- `effect_pool[0x200]` is a fixed-size C array whose `effect_discard_entry`
  fallback avoids a null check in `effect_spawn`; unlike `particle_pool` and
  `sprite_effect_pool` (which overwrite a random slot when full), a full free
  list silently drops new effects, hiding one-shot pickup and weapon feedback.

Rewrite behavior:

- Default: Both the recovered game module
  ([`crimson-core/game/effect_overflow.cpp`](../../crimson-core/game/effect_overflow.cpp))
  and the Python rewrite ([`src/crimson/effects.py`](../../src/crimson/effects.py))
  keep the original 511-slot `effect_pool` and its blood admissions
  (`effect_id == 7`) intact—preserving `crt_rand()` draws, free-list order and
  verifier snapshots—and add a 2,048-slot overflow pool and decal queue reserved
  for non-blood effects (`effect_id != 7`) when the base pool is full.
- `--preserve-bugs`: `effect_spawn` discards past 511 active entries, as native.

Evidence: `decomp/1.9/crimsonland/effects/effect_spawn.cpp`,
`decomp/1.9/crimsonland/crimsonland/projectile_update.cpp` (the piercing
microstep loop and `health > 0.0f` gate),
`decomp/1.9/crimsonland/game/bonus_apply.cpp` (the `BONUS_ID_FREEZE` corpse
loop ahead of `effect_spawn(1, ...)`), and
[`crimson-core/checks/effect_overflow.py`](../../crimson-core/checks/effect_overflow.py).

## 40) The reload key does nothing in co-op

Native behavior:

- In `player_update` (`0x004136b0`), the reload key starts a reload only when
  `config_player_count == 1`, next to the Alternate Weapon and point-and-click
  movement exclusions that give the key another job.
- With two or more players the key does nothing: a gun reloads only when its
  clip runs dry.

Why it's likely a bug:

- In co-op the key has no other job: the gate is not one of the exclusions
  where the key swaps guns or moves the player.
- The Controls screen still binds Reload for every player count, and every
  other per-player weapon rule (clip, reload time, reload perks) works the
  same with two players.

Rewrite behavior:

- Default: the reload key reloads in co-op too, under the same Alternate
  Weapon, point-and-click and empty-reload-timer conditions as in single
  player. As in the original, it is one key that every player's update
  reads.
- With `--preserve-bugs`: keep the native single-player gate.
- Replays: the fix did not raise `REPLAY_RULES`, so a co-op replay recorded
  before it with `preserve_bugs` off that pressed Reload can drift
  ([replay format](../formats/replay.md)).

Evidence: `decomp/1.9/crimsonland/gameplay/player_update_heading.cpp` (the
manual reload condition), `src/crimson/gameplay.py` (`_player_tick_reload`)
and [`crimson-core/patches/40-coop-manual-reload.patch`](../../crimson-core/patches/40-coop-manual-reload.patch).


## 41) Ion and Fire Bullets heads ignore their weapon colors

Native behavior:

- The shared `projectile_render` branch gives Ion Rifle, Ion Minigun and Ion
  Cannon trails a blue `(0.5, 0.6, 1.0)` tint, and Fire Bullets trails an orange
  `(1.0, 0.6, 0.1)` tint, in both flight and post-hit fade.
- The head after each trail loop does not branch on weapon type: every flying
  head is warm yellow `(1.0, 1.0, 0.7)`, and every fading head is ion blue
  `(0.5, 0.6, 1.0)`. The glow sprite itself is neutral white.

Why it's likely a bug:

- The trail distinguishes ion from fire in both phases, but the shared head
  does not. Ion gains a yellow nose in flight; Fire Bullets switches to blue
  after impact while its trail stays orange. These opposite mismatches point
  to missing weapon selection in the shared head draws.
- Additive SDR clipping can hide the mismatch where the head overlaps a bright
  trail; the forward fringe and HDR rendering make it easier to see.

Rewrite behavior:

- Default: heads use their trail's weapon color in both phases: blue for ion,
  orange for Fire Bullets. This applies to Python classic/RTX and the recovered
  game module shared by desktop and browser renderers.
- `--preserve-bugs`: retain the original yellow flight heads and blue fading
  heads for both weapon families. Alpha, geometry and trail colors are unchanged.

Evidence: `decomp/1.9/crimsonland/crimsonland/projectile_render.cpp`
(`0x00422c70`, the two shared head draws),
`tests/native_oracle/test_projectile_render.py` (original executable draw capture),
`tests/render/test_projectile_render.py`,
`crimson-core/checks/projectile_colors.py` (adapted renderer draw capture), and
[`41-projectile-head-colors.patch`](../../crimson-core/game/patches/41-projectile-head-colors.patch).

## 42) Jinxed can reward an already-dead creature

Native behavior:

- `perks_update_effects` selects an active creature, with up to ten retries
  for inactive slots. Dying and fading corpses remain active.
- It sets the selected creature's HP to -1 and awards its base XP without
  checking whether the creature was alive. A 100-XP corpse pays another 100
  XP when selected. This was reproduced in the original 1.9.93 executable
  under Unicorn, with controlled RNG, and in both policies of the old port.
- Breathing Room also leaves dying creatures with positive HP; checking HP
  alone would still treat those corpses as living victims.

Rewrite behavior (rules 2):

- Default: a victim must be active, have positive HP, and have the living
  lifecycle timer (`death_timer == 16`). Retry an ineligible slot using the
  existing ten-retry limit. If no living victim is found, the creature-kill
  part of this proc does nothing: no extra reward, sound, or lifecycle change.
- The accident, proc timer, Freeze gate, base-only reward, and no-drop kill
  semantics stay as before. This fixes victim eligibility, not all special
  death paths. Rejecting corpses can consume extra retry RNG draws.
- With `--preserve-bugs`: retain active-only selection and duplicate rewards.

**1.9.8:** shared, with the same treatment. 1.9.8 also has no Freeze gate, so
its Jinxed kills during Freeze too: see
[57)](#57-jinxed-kills-creatures-during-freeze-198-only).

Evidence: `decomp/1.9/crimsonland/game/perks_update_effects.cpp:194-211`,
`tests/perks/test_jinxed_perk.py`, and
[`42-jinxed-living-target.patch`](../../crimson-core/patches/42-jinxed-living-target.patch).

## 43) Co-op randomized perk intervals reschedule the other player

Fire Cough and Hot Tempered have per-player elapsed timers but global next
intervals. One player's proc changes the threshold the other player is waiting
for. Two due players can therefore produce only one shot/ring.

Default (rules 2): each player owns both elapsed time and next interval. Keep
initial delay 1.4 seconds, Fire Cough's 2–5 second distribution, Hot Tempered's
2–9 seconds, and the shared deterministic RNG. There is no artificial phase
shift: simultaneous first procs are allowed. Man Bomb's constant interval is
unchanged. `--preserve-bugs` retains the shared randomized thresholds.

Added state is reset with each run, compared in Python/core snapshots, hashed
in co-op, and restored by watch/practice/rollback keyframes without changing
the recovered player structure. [Issue #821](https://github.com/banteg/crimson/issues/821),
`43-independent-perk-intervals.patch`, `tests/gameplay/test_rules2_bundle.py`.

**1.9.8:** shared for Hot Tempered only, which keeps the same treatment. 1.9.8
has no Fire Cough.

## 44) Alternate Weapon uses stale readiness and a shared cooldown

The original captures normal/perk firing eligibility before swapping slots.
It can fire the incoming weapon despite its reload or cooldown and charge the
incoming weapon's XP/HP cost using the outgoing weapon's readiness.

Default: evaluate the incoming weapon after adding the existing 0.1-second
swap delay. Each player owns their 200 ms swap cooldown and release handling.
`--preserve-bugs` retains the shared cooldown and pre-swap firing gate.

**Reachability:** Alternate Weapon is not offered in normal co-op. The firing
bug is reachable solo; shared-cooldown interference requires granting the perk
to a co-op run. Availability is unchanged. [Issue #822](https://github.com/banteg/crimson/issues/822),
`44-independent-weapon-swap.patch`, `tests/perks/test_alternate_weapon_perk.py`.

## 45) Negative health subtracts from the quest life bonus

A dead partner at -80 HP adds four seconds to a quest result compared with
zero HP. Overkill damage should not be a negative life bonus.

Default: clamp every player's contribution to zero before the existing
seat-specific rounding. Preserve negative final times and the exactly-zero
1 ms sentinel. `--preserve-bugs` retains negative-HP contributions. Python,
core results, recovered results UI, and service verification use the same
policy. Historical run pages retain the formula matching their stored score.
[Issue #823](https://github.com/banteg/crimson/issues/823), `45-quest-life-bonus.patch`.

## 46) Rocket detonation handles a lethal hit twice

The ordinary damage path already handles death; detonation calls the handler
again. A 100-XP victim pays 200 XP, bonus rolls repeat, and a splitter creates
four children instead of two.

Default: call death handling once, retaining the two follow-up random decals.
`--preserve-bugs` retains the duplicate rewards, drops and splits. This is a
real rocket economy change, even though it removes an accidental duplicate.
[Issue #824](https://github.com/banteg/crimson/issues/824), `46-single-rocket-death.patch`.

## 47) Shock Chain continuation targets corpses

Initial target selection checks the living lifecycle; continuation originally
checks only active slots. It can spend links on bodies and even return to an
earlier corpse. Zero-HP slots with a living timer can also pass the initial query.

Default: both searches require positive HP and `death_timer == 16`, retaining
exclude-id, distance bounds, slot ordering and the existing no-target result.
Seeker Rockets share the initial query, so they also stop selecting zero-HP
slots whose lifecycle timer still says living.
`--preserve-bugs` retains each query's original predicate and fallback.
[Issue #825](https://github.com/banteg/crimson/issues/825), `47-living-chain-targets.patch`.

## 48) Plague and Radioactive miss zero-HP kills and continue live behavior

Both pulse paths test strictly negative HP. An exact-zero hit misses the
reward; an overkill can continue into live AI/ranged/contact logic that tick.

Default: treat zero as lethal and leave the live branch after the existing
pulse effects. Plague keeps ordinary death rewards; Radioactive keeps base XP,
no drops/splits and its lizard exemption, including at equality. Corpses begin
their normal update on the next tick. `--preserve-bugs` keeps strict-negative
tests and live-branch fallthrough. [Issue #826](https://github.com/banteg/crimson/issues/826),
`48-dot-death-boundaries.patch`.

**1.9.8:** shared, with the same treatment. 1.9.8's Radioactive has no lizard
exemption (a 1.9.8 rule: a lethal pulse kills a lizard like any other
creature) and no `health > 0` gate ([56)](#56-radioactive-burns-creatures-already-at-zero-health-or-below-198-only)).

## 49) Death slides ignore impact direction; primary impulses use cosine twice

The original overwrites corpse velocity from its heading every tick. Primary
hits also use the same cosine for both impulse components. The latter can
already affect living HOLD_TIMER creatures through contact movement.

Default: use sine for the primary impulse Y component. On a lethal hit with a
nonzero impulse, align the corpse heading so the existing backward slide
travels along that impulse. Rockets supply their outward impulse; Nuke aligns
newly killed victims outward without adding a live-creature impulse. Rotation
happens after death handling so splitter children inherit the pre-death state.

Zero-direction hits and special deaths retain their heading. Pinned spawners
never slide, so they keep their heading too and their dead frame lines up with
the living one; mobile spawners retain their existing slide eligibility.
Slide speed, duration, corpse collision window and piercing damage pools are
unchanged. The heading also determines the collapsed sprite orientation.
`--preserve-bugs` retains cosine/cosine impulses and heading-based original slides.
[Issue #818](https://github.com/banteg/crimson/issues/818), `49-impact-aligned-death.patch`.


## 50) Fire Bullets loses Gauss Shotgun and Multi-Plasma pellets

Normal firing emits six Gauss Shotgun projectiles and five Multi-Plasma bolts,
but metadata supplies one and three respectively to Fire Bullets conversion.
Rules 2 default uses six/five converted projectiles and the existing multi-pellet
cadence: 1.05 seconds for Gauss Shotgun and approximately 0.6208117 seconds for
Multi-Plasma before perks. Rules 1 and `--preserve-bugs` retain the old conversion.

This is an adopted consistency/balance choice. Gauss previously used the
single-pellet 0.14-second Fire Bullets cooldown, so this increases burst size
while reducing nominal projectiles per second. Multi-Plasma converts its three
strong/two weaker bolts into five uniform Fire Bullets. Normal firing, ammo
suppression during the bonus, perk multipliers, spread and casing flags retain
their existing behavior. Muzzle brightness follows the existing multi-pellet
branch. Legacy weapon metadata remains unchanged.
[Issue #832](https://github.com/banteg/crimson/issues/832), `50-fire-bullets-conversion.patch`.

**1.9.8:** absent. 1.9.8 has no Fire Bullets volley: each Gauss Shotgun and
Multi-Plasma projectile gains its own Fire Bullets shot, six and five, at the
weapon's own cadence, under both policies.

## 51) Piercing damage pools grow on overkill (documented, not fixed)

Gauss Gun, Fire Bullets and Blade Gun projectiles start with a damage pool of
300, 240 and 50. Each hit spends 1, deals the rest of the pool, then subtracts
the target's health *after* the hit. An overkill leaves negative health, so the
pool grows: with no perks, a pool `P` against a target with `H` health leaves
`2 * (P - 1) - H`. One Gauss shot through three 50-HP targets leaves pools of
548, 1,044 and 2,036; the shot keeps piercing as long as it keeps killing.

Why it stays:

- Fire Bullets is the bonus that clears crowds in the original, and much of
  that comes from pool growth. In the recorded human Survival runs, Fire Bullets
  makes 28-41% of all kills, and 11-27% of those need a pool larger than one
  that only shrank. Fixing it is a large
  nerf to the main Survival bonus, and boards combine rules versions.
- There is no intended behavior to restore. A spent-budget pool is undefined
  under damage perks: subtracting raw health or perk-modified damage either
  ignores Uranium Filled Bullets or compounds it across hits.

Both bug policies keep the original arithmetic. A change belongs to a
deliberate balance pass with its own rules version, not to this ledger.
[Issue #820](https://github.com/banteg/crimson/issues/820).

## 52) Shots past the arena edge stop and fade in place

Native behavior:

- `projectile_update` stops a shot once it is 64 units past the terrain and
  starts its life timer running down: the shot takes the 0.4-second fade a hit
  gives it, standing still.
- `projectile_render` draws a fading shot's last 256 units of path, so the trail
  of a shot that left the arena hangs at its edge, most of it on screen when the
  view reaches the edge, and fades there.

Why it's likely a bug:

- Nothing was hit: the stop only retires a shot that is out of play. A Fire
  Bullets shot passes through what it hits, so past the edge only the stop can
  have faded it, and its trail freezes where it should keep flying off.

Rewrite behavior:

- Default: a Fire Bullets shot past the edge is drawn, and lit in RTX, flying on
  along its path at its own speed while it fades, so its trail leaves the screen.
  The simulation is unchanged: the shot still stops and fades as in the original.
  Ion shots keep the original look: a hit also fades them, and creatures outside
  the arena can be hit, so their fade there is not always the edge's.
- `--preserve-bugs`: trails freeze at the edge as in the original.

Evidence: `decomp/1.9/crimsonland/crimsonland/projectile_update.cpp` (the
out-of-bounds branch), `decomp/1.9/crimsonland/crimsonland/projectile_render.cpp`
(the fading streak), `tests/render/test_material_lights.py`, and
[`52-fire-bullets-fly-off.patch`](../../crimson-core/game/patches/52-fire-bullets-fly-off.patch).


## 53) The console key and console typing reach the name field

Native behavior:

- Grim's window procedure queues each typed character (`WM_CHAR`) for
  `console_input_poll` and also writes it straight into the buffer the last
  `ui_text_input_update` bound. It keeps out only Tab and `§`, the console key's
  character on a Finnish keyboard.
- `game_frame_update` opens the console on the key left of 1 (DirectInput
  `0x29`). On other layouts that key types another character, `` ` `` on a US
  keyboard, which reaches the field before the console opens; opening flushes
  the queue but not the field.
- While the console is open, `console_input_poll` takes the queue, but the
  window procedure still writes every character into the bound field: on the
  high score name entry, a console command also lands in the name.

Why it's likely a bug:

- The `§` filter shows the console key's character was meant to stay out of
  text fields; it covered the developers' own layout only.
- An open console takes the keyboard: it pauses the game and takes Enter away
  from the field, but the field keeps getting its text.

Rewrite behavior:

- The Python port's console drains typed text as it opens, closes and reads it,
  so the port's text fields never get it.
- The web and native clients drop what is typed while the console key is down,
  on any layout, and leave the bound field alone while the console is open.
  Their `WM_CHAR` (`game_key_char` in
  [`crimson-core/game/frame.cpp`](../../crimson-core/game/frame.cpp)) stands in
  for the window procedure, so the fix lives there rather than in a patch.
- `--preserve-bugs` has nothing to restore: the Python port never had the leak,
  and the clients' fix changes no run, only where typed text lands. Typ-o reads
  the queue, whose console key character the console's opening flushed anyway.

Evidence: `decomp/1.9/grim/window/window_proc.cpp` (`WM_CHAR`),
`decomp/1.9/crimsonland/ui_widgets/ui_text_input_update.cpp`,
`decomp/1.9/crimsonland/console/console_input_poll.cpp`,
`decomp/1.9/crimsonland/console/console_set_open.cpp`, the console toggle in
`decomp/1.9/crimsonland/game/game_frame_update.cpp`, and
[`checks/game_session.mjs`](../../crimson-core/checks/game_session.mjs).


## 54) A Shrinkifier kill pays twice, and once more on the corpse (documented, not fixed)

Native behavior:

- `projectile_update`'s Shrinkifier branch shrinks the target to 65% and calls
  `creature_handle_death` once it drops below size 16, then falls through to
  the shot's ordinary damage. A shrink kill leaves health as it was, so when
  that damage (9.5) finishes what is left, it kills the same creature again:
  two rewards, two bonus rolls. A target with more health left pays once.
- The death keeps the corpse active, and a corpse stays hittable while its
  death timer is above 5. The next Shrinkifier shot shrinks it below 16 again
  and handles its death a third time.

A size-50, 20 HP, 110 XP alien (`ALIEN_CONST_GREEN_24`) dies on the third hit
for 220 XP; firing on at the weapon's 0.21 s rate, the fourth hit pays 110
more, and the corpse is out of reach by the fifth. Frozen targets pay once:
Freeze removes the body on its first death.

Why it stays:

- It's a real economy bug, but the Shrinkifier is a one-run secret Survival
  reward ([how to get it](../mechanics/secret-weapons.md#shrinkifier-5k)), and
  fixing it changes kills, rewards and drops: a new rules version, not a patch.
  Both bug policies keep the original sequence.

Evidence: `decomp/1.9/crimsonland/crimsonland/projectile_update.cpp` (the
Shrinkifier branch and the damage after it),
`decomp/1.9/crimsonland/crimsonland/creature_handle_death.cpp` (the active
check), `decomp/1.9/crimsonland/crimsonland/creature_find_in_radius.cpp` (the
corpse cutoff), and `src/crimson/projectiles/runtime/projectile_pool.py`.

## 55) An expiring bubble kills whatever holds its creature slot (documented, not fixed)

Native behavior:

- A Bubblegun bubble that lands stores only its target's creature slot. When it
  expires it calls `creature_handle_death` on that slot, with no check that the
  creature there is still the one it hit. The active check before it only
  picks the death sound.
- If the target died and a new creature took the slot, the bubble kills the new
  one wherever it is, with its rewards, drops, splits and Freeze shatter.

Why it stays:

- Nothing hands out the Bubblegun (weapon 42): the weapon picker, quest unlocks
  and Survival rewards all stop at weapon 33, so no normal run can fire one.

Evidence: `decomp/1.9/crimsonland/crimsonland/projectile_update.cpp` (the
particle expiry) and `src/crimson/effects.py` (the bubble's attach and expiry).

## 56) Radioactive burns creatures already at zero health or below (1.9.8 only)

1.9.8 only (`CL_BUILD == 10908`); 1.9.93 burns only creatures with health above
zero.

Native behavior:

- In 1.9.8's `creature_update_all` (`0x00425950`), a Radioactive pulse hurts a
  creature within 100 units of its target player whenever the creature's pulse
  timer runs out, with no health check. A pulse that leaves it below zero adds
  its reward to player 1's XP and takes a frame off its death timer.
- A creature can die earlier in its own update and still reach the pulse: one
  tethered to a creature that has died takes 1000 damage there, and death
  handling pays its reward. If its pulse timer runs out on that frame, the
  pulse burns the corpse and pays its base XP again.

Why it's likely a bug:

- A dead creature has already paid for its kill; the pulse pays the same kill
  again.
- 1.9.93 adds the check together with the lizard exemption, under notes that
  list "Fixed Radioactive perk and Spideroids bug". The 1.9.9 and 1.9.92
  executables still pulse without either.

Rewrite behavior:

- Default: pulses skip creatures at zero health or below, as in 1.9.93.
- `--preserve-bugs`: a 1.9.8 run pulses them and pays again, as native.
- Lizards die to the pulse in a 1.9.8 run under both policies: that is one of
  the [1.9.8 rules](rules-1.9.8.md), not this entry.

Evidence: `decomp/1.9/crimsonland/crimsonland/creature_update_all.cpp` (the
guarded Radioactive branch, and the 1000-damage tether kills before it), and
the Radioactive branch of `creature_update_all` in the 1.9.8, 1.9.9
(`0x00426380`) and 1.9.92 (`0x00426510`) executables in `game_bins/crimsonland/`.
Tests: `tests/creatures/test_radioactive_pulse.py`.

## 57) Jinxed kills creatures during Freeze (1.9.8 only)

1.9.8 only (`CL_BUILD == 10908`); 1.9.93 skips the kill while Freeze is active.

Native behavior:

- In 1.9.8's `perks_update_effects` (`0x00405b60`), every Jinxed proc runs the
  random kill, Freeze or not: it picks a creature slot with up to ten retries,
  sets the creature's health to -1, cuts its death timer, pays its base XP and
  plays the Jinxed kill sound.
- 1.9.93 returns after the accident roll and the next proc delay while
  `bonus_freeze_timer` runs, so during Freeze a 1.9.8 run also draws the slot
  pick and its retries.

Why it's likely a bug:

- Freeze pauses the creature update, and with it the creature's own damage
  over time: Plague, Radioactive and poison. 1.9.93 pauses Jinxed's kill along
  with them.
- The gate first appears in 1.9.92 among
  [recovered builds](../re/static/reference/history.md); 1.9.9 has none. The
  notes of 1.9.91 and 1.9.92 have no line for it beyond "Minor bug fixes", and
  1.9.91 is not recovered.

Rewrite behavior:

- Default: Jinxed kills nothing while Freeze is active, as in 1.9.93.
- `--preserve-bugs`: a 1.9.8 run kills during Freeze too, as native.
- Victim selection follows
  [original bug 42](#42-jinxed-can-reward-an-already-dead-creature) either way.

Evidence: `decomp/1.9/crimsonland/game/perks_update_effects.cpp` (the Freeze
return before the creature pick, under `CL_JINXED_RESPECTS_FREEZE`, which
[`cl_rules.h`](../../tools/match/include/cl_rules.h) sets by build and
[`host/rules.h`](../../crimson-core/host/rules.h) by a run's build and bug
policy), and
`perks_update_effects` in the 1.9.9 (`0x00406b80`) and 1.9.92 (`0x00406bd0`)
executables, of which only 1.9.92 reads `bonus_freeze_timer`. Tests:
`tests/perks/test_jinxed_perk.py`.

## 58) Infernal Contract revives a dead player 1 and spares player 2 in co-op (1.9.8 only)

1.9.8 only (`CL_BUILD == 10908`); 1.9.93 drops every living player to 0.1
health.

Native behavior:

- 1.9.8's `perk_apply` (`0x00404660`) grants the three levels and perks, then
  writes 0.1 to player 1's health (`0x00404839`) without checking it, and
  leaves player 2's alone.
- In co-op, taking the perk while player 1 is dead brings them back at 0.1
  health, and player 2 keeps theirs.

Why it's likely a bug:

- The price is near-death health for whoever takes the deal, and in co-op both
  players get its perks. Writing player 1's slot alone charges one player, even
  a dead one, and lets the other go free.
- 1.9.9 already checks each player's health and sets both (`perk_apply`,
  `0x00405620`); its notes have no line for the fix beyond "Minor bug fixes".

Rewrite behavior:

- Default: every living player drops to 0.1 health, as in 1.9.93.
- `--preserve-bugs`: a 1.9.8 run sets player 1's health to 0.1, alive or dead,
  and leaves player 2's alone, as native.

Evidence: `decomp/1.9/crimsonland/game/perk_apply.cpp` (the Infernal Contract
branch), and `perk_apply` in the 1.9.8 and 1.9.9 executables. Tests:
`tests/perks/test_infernal_contract_perk.py`.

## 59) My Favourite Weapon's clip bonus is lost on the next weapon (1.9.8 only)

1.9.8 only (`CL_BUILD == 10908`); 1.9.93 adds the bonus to every weapon a
player gets while the perk is held.

Native behavior:

- Taking My Favourite Weapon adds 2 to each player's current clip size
  (`perk_apply`), in both builds.
- 1.9.8's `weapon_assign_player` (`0x00450940`) sets the clip from the weapon
  table and Ammo Maniac, and never adds the 2. The next weapon a player gets
  loses it for good: a Weapon pickup, Random Weapon, a Survival secret weapon,
  or Ammo Maniac, which reassigns the current weapon to enlarge its clip.

Why it's likely a bug:

- The perk promises "+2 clip size" for good, and taking Ammo Maniac after it
  should not shrink the clip.
- The bonus on assignment first appears in 1.9.92 among recovered builds
  (1.9.9 has none), under notes that list "Minor bug fixes".

Rewrite behavior:

- Default: every assignment adds the 2 while the perk is held, as in 1.9.93.
- `--preserve-bugs`: a 1.9.8 run adds it only when the perk is taken, as
  native.

Evidence: `decomp/1.9/crimsonland/weapons/weapon_assign_player.cpp` (the
`CL_BUILD != 10908` bonus), `decomp/1.9/crimsonland/game/perk_apply.cpp` (the
pick-time bonus and the Ammo Maniac reassignment), and `weapon_assign_player`
in the 1.9.9 (`0x00452dc0`) and 1.9.92 (`0x00452fa0`) executables. Tests:
`tests/weapons/test_weapon_assign_side_effects.py`.

## 60) My Favourite Weapon lets the Pistol's forced Weapon drops through (1.9.8 only)

1.9.8 only (`CL_BUILD == 10908`); 1.9.93 cancels them while the perk is held.

Native behavior:

- `bonus_try_spawn_on_kill` (1.9.8: `0x0041f140`) first tries a forced Weapon
  drop on 3 kills in 4 while player 1, or player 2 in a two-player game, holds
  the Pistol. This drop bypasses `bonus_pick_random_type`, which rerolls Weapon
  bonuses for My Favourite Weapon in both builds.
- 1.9.93 cancels the forced drop while the perk is held. 1.9.8 cancels it only
  when its weapon roll gives the Pistol twice or another Weapon drop is on the
  ground, so a Pistol holder with the perk still gets weapon drops.

Why it's likely a bug:

- The perk text promises "no more random weapon bonuses", and the normal drop
  path keeps that promise; only the Pistol's path misses it.
- The check first appears in 1.9.92 among recovered builds (1.9.9 has none),
  under notes that list "Minor bug fixes".

Rewrite behavior:

- Default: no forced Weapon drop while the perk is held, as in 1.9.93.
- `--preserve-bugs`: a 1.9.8 run lets it through, as native. Picking it up
  then also loses the clip bonus
  ([59)](#59-my-favourite-weapons-clip-bonus-is-lost-on-the-next-weapon-198-only)).

Evidence: `decomp/1.9/crimsonland/crimsonland/bonus_try_spawn_on_kill.cpp` (the
`CL_BUILD != 10908` term in the forced drop's reject), and
`bonus_try_spawn_on_kill` in the 1.9.9 (`0x0041fa70`) and 1.9.92 (`0x0041fbc0`)
executables. Tests: `tests/bonuses/test_bonus_pistol_rules.py`.
