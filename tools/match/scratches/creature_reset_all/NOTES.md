# `creature_reset_all`

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare; `flags[-5]` is spelled `link_index`. The source stays exact, byte for byte. Any older description below of the replaced spelling is historical. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).

Exact 46-byte, 13-instruction match with MSVC 6.5 `/O2 /GB`.

Live Binary Ninja shows one caller, `quest_start_selected` at `0x0043a797`.
The helper walks all 384 static creature records, clears only `active`, and,
for flag bit `0x04`, nulls the owner pointer in the linked spawn slot. Every
other creature field remains stale. Native spawn slots store creature pointers,
so their null owner corresponds to the ports' `-1` index sentinel rather than
creature index zero.

`game_state_set` calls `gameplay_reset_state` immediately before the quest
helper. Its reset-time round-robin `target_player` assignments therefore
survive into quest allocation and are modeled separately in both ports.
