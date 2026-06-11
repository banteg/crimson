# Original bugs (rewrite)

The classic `crimsonland.exe` has a few behaviors that look like genuine bugs
once you read the decompile and trace their gameplay impact.

In the rewrite, we fix these **by default**. For parity work and future
differential testing, you can re-enable them with `--preserve-bugs`.

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

- `Reflex Boost` (`amount=3`) while holding `Shotgun` (`weapon_id=3`)
- `Fire Bullets` (`amount=4`) while holding `Sawed-off Shotgun` (`weapon_id=4`)
- `Freeze` (`amount=5`) while holding `Submachine Gun` (`weapon_id=5`)
- `Shield` (`amount=7`) while holding `Mean Minigun` (`weapon_id=7`)
- `Speed` (`amount=8`) while holding `Flamethrower` (`weapon_id=8`)
- `Weapon Power Up` / `MediKit` (`amount=10`) while holding `Multi-Plasma` (`weapon_id=10`)

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

## 4) Player-facing text typos are preserved in native data

Native behavior:

- User-facing strings include spelling/grammar mistakes in both:
  - gameplay data tables (perk/weapon/bonus labels/descriptions), and
  - screen/UI copy.
- Source evidence: `analysis/ghidra/raw/crimsonland.exe_strings.txt`.

Why it’s likely a bug:

- These are straightforward spelling/wording mistakes in user-facing text, not
  gameplay semantics.

Rewrite behavior:

- Default: display corrected text in the rewrite.
- With `--preserve-bugs`: keep the original misspelled strings for parity
  captures/testing.

Full gated text-fix list:

| Area | Native text (`--preserve-bugs`) | Default rewrite text |
| --- | --- | --- |
| Perk name | `Fire Caugh` | `Fire Cough` |
| Weapon name | `Plague Sphreader Gun` | `Plague Spreader Gun` |
| Weapon name | `Lighting Rifle` | `Lightning Rifle` |
| Weapon name | `Fire bullets` | `Fire Bullets` |
| Perk description (`Anxious Loader`) | `waiting your gun to be reloaded` | `waiting for your gun to be reloaded` |
| Perk description (`Dodger`) | `attacks you you have a chance` | `attacks you, you have a chance` |
| Perk description (`Ninja`) | `have really hard time` | `have a really hard time` |
| Perk description (`Living Fortress`) | `It comes a time ... Being living fortress ... You do the more damage ...` | `There comes a time ... Being a living fortress ... You do more damage ...` |
| Bonus description (`Weapon Power Up`) | `Your firerate and load time increase for a short period.` | `Your fire rate and load time increase for a short period.` |
| Bonus description (`Fire Bullets`) | `For few seconds -- make them count.` | `For a few seconds -- make them count.` |
| End note line | `You've completed all the levels but the battle` | `You've completed all the levels, but the battle` |
| Quest failed line | `Persistence will be rewared.` | `Persistence will be rewarded.` |
| Tutorial hint | `Picking it you gets a new weapon.` | `Picking it up gives you a new weapon.` |
| Tutorial hint | `exposion` | `explosion` |
| Weapon database panel label | `wepno #<id>` | `weapon #<id>` |
| Weapon database panel label | `Firerate` | `Fire rate` |
| Perk database panel label | `perkno #<id>` | `perk #<id>` |
| Quest results prompt | `State your name trooper!` | `State your name, trooper!` |
| Game over hit-ratio tooltip | `The % of shot bullets hit the target` | `The % of bullets that hit the target` |
| Statistics panel line | `played for 1 hours 1 minutes` | `played for 1 hour 1 minute` |

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

Why it’s likely a bug:

- The intent is clearly “refill ammo when reload completes”; the underflow check
  just fails to account for the Stationary Reloader scale factor.

Rewrite behavior:

- Default: use the scaled reload decrement (`reload_scale * frame_dt`) for the preload
  check so ammo is always refilled when Stationary Reloader causes same-tick completion.
- With `--preserve-bugs`: keep the native unscaled preload check (and the empty-reload loop).

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

- In `player_fire_weapon` (`0x00416a50`), Mini-Rocket Swarmers set per-rocket
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

## 19) Co-op auto-target replacement compares against player 1 position

Native behavior:

- In `creature_update_all` (`0x00426220`), once a creature picks its
  `target_player`, the auto-target replacement check compares the new creature’s
  distance against the current auto-target distance.
- For player 2, the current auto-target distance is measured from
  `player_state_table.pos_x/pos_y` (player 1) instead of player 2’s own
  position, then written back to `player2.auto_target`.

Why it’s likely a bug:

- The compare/write pair is otherwise indexed to the chosen target player.
- In co-op this can leave player 2 stuck on a worse auto-target simply because
  the previous target was closer to player 1.

Rewrite behavior:

- Default: compare both the new creature and the current auto-target against the
  targeted player’s own position.
- With `--preserve-bugs`: keep native player-1-sourced distance bias for player
  2 auto-target replacement.

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
  `creature_type_table[5].sfx_bank_a[0..2]` only.
- `creature_apply_damage` (`0x004207c0`) still resolves trooper death audio with
  `sfx_bank_a[rand & 3]`.
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
