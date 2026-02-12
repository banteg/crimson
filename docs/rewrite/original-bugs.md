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

- Default: only suppress `Weapon` drops that match the current weapon id.
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
- It multiplies each alive player's health by `roll`, then clamps to `100`.

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

- Some perk/weapon/bonus strings include spelling mistakes carried in the
  executable data tables.
- Examples:
  - Perk: `Fire Caugh`
  - Weapon: `Plague Sphreader Gun`
  - Weapon: `Lighting Rifle`
  - Bonus text: `firerate`, `For few seconds`

Why it’s likely a bug:

- These are straightforward spelling/wording mistakes in user-facing text, not
  gameplay semantics.

Rewrite behavior:

- Default: display corrected text in the rewrite.
- With `--preserve-bugs`: keep the original misspelled strings for parity
  captures/testing.
