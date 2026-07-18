# `player_take_damage`

Native target: `crimsonland.exe` at `0x00425e50` (969 bytes).

The recovered C++ is exact: 267/267 instructions with a full 267-instruction
prefix and 73/0/0 reference agreement. It preserves the original control-flow
shape around dodge handling, the strict `health < 0.0f` lethal branch, the
player-1 pre-hit alive guard, Final Revenge's inline radius blast, and the
post-hit heading/spread updates.

Every perk query is a call to the global `perk_count_get`; unlike the indexed
health, shield, reload, position, and timer fields, it always reads player 1.
This includes Death Clock, Tough Reloader, Thick Skinned, Ninja, Dodger,
Highlander, Final Revenge, and Unstoppable. The Python and Zig ports therefore
use player 1 as the perk/alive source under `preserve_bugs`, while corrected
mode keeps the damaged player's perks. Final Revenge also retains native's
strict-negative lethal boundary and is suppressed when player 1 was already
dead before the hit.
