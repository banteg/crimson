# weapon_refresh_available

## Plausibility pass (2026-09-25)

The whole function is now plain source: indexed loops and direct `= 1` stores. The `one` register local, byte casts and cursor guard were unnecessary. The source stays exact, byte for byte. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).
