# `player_take_damage`

Native target: `crimsonland.exe` at `0x00425e50` (969 bytes).

The recovered C++ is exact: 267/267 instructions with a full 267-instruction
prefix and 73/0/0 reference agreement. It preserves the original control-flow
shape around dodge handling, the strict `health < 0.0f` lethal branch, the
player-1 pre-hit alive guard, Final Revenge's inline radius blast, and the
post-hit heading/spread updates.

Live Binary Ninja xrefs show exactly two native callers: `player_update` at
`0x00415a03` (the Ammunition Within reload path) and `creature_update_all` at
`0x00427346` (contact damage). Final Revenge therefore runs synchronously only
from those two calls. Direct health stores in `projectile_update`, Death Clock,
and Jinxed bypass the blast entirely. The Python and Zig runtimes preserve that
scope; Zig also forwards the real frame dt through Ammunition Within so a lethal
cost performs the native `death_timer -= frame_dt * 28.0f` update before weapon
execution continues.

Final Revenge sets `bonus_spawn_guard` to `1` at `0x00426004`, scans the full
384-entry creature pool, then unconditionally stores `0` at `0x004260ef`
before its sound effects. This is a literal reset, not restoration of an
incoming guard value; Python and Zig preserve that transition and exercise it
from an initially set guard.

Final Revenge's embedded player position and zero force are now recovered as
`const vec2f_t *player_pos` and `vec2f_t impulse`. Named components replace the
four remaining raw indexes in the exact source. Binary Ninja independently
shows the impulse aggregate, and its position cursor is saved with the same
read-only vector type. All 267 instructions and 73 references remain exact.
The ordinary death and pain audio branches likewise pass
`player_state_t::position` directly instead of casting from `pos_x`.

Every perk query is a call to the global `perk_count_get`; unlike the indexed
health, shield, reload, position, and timer fields, it always reads player 1.
This includes Death Clock, Tough Reloader, Thick Skinned, Ninja, Dodger,
Highlander, Final Revenge, and Unstoppable. The Python and Zig ports therefore
use player 1 as the perk/alive source under `preserve_bugs`, while corrected
mode keeps the damaged player's perks. Final Revenge also retains native's
strict-negative lethal boundary and is suppressed when player 1 was already
dead before the hit.

The remaining creature/player distance operand now names both canonical
position aggregates. This complements the already-typed Final Revenge
arguments and remains byte-for-byte exact at 267/267 instructions and 73/0/0
references.
