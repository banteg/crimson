# grim_destroy_texture

## Plausibility pass (2026-09-27)

The cached `grim_texture_slot_max_index` local was dropped in favour of a direct compare and decrement. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md).
