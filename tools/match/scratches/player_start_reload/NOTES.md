# `player_start_reload`

Native target: `crimsonland.exe` at `0x00413430` (263 bytes).

The recovered C source matches all 67 normalized instructions and all 28
masked references. Live Binary Ninja shows four native callers: two in
`player_update` and two in Typ-o Shooter's `player_fire_weapon`.

The helper mutates the overlay-selected player but deliberately obtains
Ammunition Within and Regression Bullets through `perk_count_get`, whose exact
implementation always reads player slot 0. Its Fastloader check also indexes
`player_state_table[0].perk_counts` directly. Thus player 0 can suppress a
player 1 reload refresh or shorten player 1's reload, while player 1's own
copies of those perks do not affect the helper.

Both ports now preserve this slot-zero source when `preserve_bugs` is enabled
and a player slice is available. Corrected mode retains per-player perk
ownership. Focused co-op regressions cover both the Fastloader scaling and the
active-reload early-return gate.

The helper's local position cursor is now a `const vec2f_t *` pointing at the
player aggregate before the panned reload call. This removes the raw member
offset boundary without changing the exact 67/67 instruction, 28-reference
match.
