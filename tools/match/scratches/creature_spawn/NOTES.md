# `creature_spawn`

Native target: `crimsonland.exe` at `0x00428240` (334 bytes).

Live Binary Ninja evidence recovers the complete rush-mode creature
initializer. It allocates one creature slot, copies the caller's position and
type, and initializes orbit-player AI with cleared collision, force-target,
attack-cooldown, and velocity state. The creature starts active with state flag
one and lifecycle stage 16. Its elapsed-time-derived values are:

- health: `survival_elapsed_ms * 0.000100000005 + 10`;
- move speed: `survival_elapsed_ms * 1.00000007e-5 + 2.5`;
- size: `survival_elapsed_ms * 1.00000007e-5 + 47`.

The function consumes two random draws. Heading is `(rand() % 314) * 0.01`,
and reward is `rand() % 30 + 140`. It copies all four caller-provided tint
components, sets contact damage to four, and copies health into max health
before returning the allocated slot.

The legacy `oldtypes.h` declaration `SpawnCreatureEx(vec2_t spot, color_t col,
int)` proves the two caller aggregates. The lowered matching boundary now uses
`const vec2f_t *pos` and `const effect_color_t *tint`; source and saved Binary
Ninja types expose `x`/`y` and `r`/`g`/`b`/`a` instead of six raw float
indexes. The destination position is likewise copied through the canonical
`creature_t::position` aggregate instead of two provisional scalar aliases.
That source-shape recovery is byte-neutral. Binary Ninja also types the
embedded destination beginning at `creature_t::tint_r` as
`effect_color_t *creature_tint`.

The native function explicitly materializes two zero words in its eight-byte
stack frame before reading them back as the creature velocity. The matching
source keeps that observed storage overlay, but names its float view as a
`vec2f_t zero_velocity` instead of exposing anonymous parallel `int[2]` and
`float[2]` indexes. A plain initialized `vec2f_t` is not equivalent under this
C front end: VC6 folds it away, deleting the native frame and six
instructions. The named overlay is byte-neutral at 86.08%, 79/79 instructions,
and 27/0/0 references.

The candidate has the exact 79-instruction length, resolves all 27 audited
references, and scores 86.08% with a seven-instruction exact prefix. Its
remaining differences are instruction scheduling rather than missing behavior:
the scratch compiler hoists the first elapsed-time x87 calculation through
independent record stores and starts the final size calculation during the tint
copy, while native leaves both calculations close to their stores.

The direct `creature_pool[slot_id]` form is significant. Replacing it with a
local `creature_t*` changes the native global-base-plus-index addressing into
an absolute record pointer, drops one instruction, loses reference alignment,
and falls to 61.15%. Compiling the identical source as C++ or with `msvc6.6`
does not change the best candidate; `msvc6.5pp` and `/G6` regress to 83.54%
and 75.95%. No volatile state, artificial aliases, dummy work, or ordering
barriers are used.

The Python and Zig rush-mode spawn models already preserve the native formulas,
two RNG call sites, four-component tint, and max-health copy, so this audit did
not reveal a port-parity correction.
