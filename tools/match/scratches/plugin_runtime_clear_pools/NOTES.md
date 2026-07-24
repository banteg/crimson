# plugin_runtime_clear_pools

Native target: `crimsonland.exe` at `0x0040b5d0` (89 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 24/24
normalized instructions, full prefix, and masked references `8/0/0`.

## Recovered source shape

- All 16 bonus slots are reset to the `BONUS_ID_NONE` sentinel.
- The 384 creature records clear their active byte and set health to `-1.0f`.
- The 96 projectile records clear their active byte.
- Both player records clear the active byte and set health to `-1.0f`. The
  native loop carries a cursor to the health field, which exposes the original
  `0x360`-byte player record stride and the active byte at offset zero.
- The health cursor is converted back to its containing `player_state_t` with
  `offsetof(player_state_t, health)`, so the active-byte write and loop bound
  now use the canonical `entity_active` and `player_state_table[2].health`
  fields. This also removes the scratch-local duplicate player layout. A
  shadow probe preserved the exact 24/24 instructions and all eight references.
- Signed loop indices naturally reproduce the native address-sentinel loops;
  no address constants are forced in the source.

No inline assembly, volatile state, dummy dependencies, or layout-only control
flow is used.
