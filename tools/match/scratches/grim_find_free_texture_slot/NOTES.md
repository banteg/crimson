# grim_find_free_texture_slot

## Plausibility pass (2026-09-27)

The int-cast pointer walk over a `void *` alias of the slot table, and its `goto`, became an indexed `for` loop over `grim_texture_slots` from `grim_texture.h` that returns the first empty index. Strength reduction and linear test replacement produce the same signed pointer compare. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md).
