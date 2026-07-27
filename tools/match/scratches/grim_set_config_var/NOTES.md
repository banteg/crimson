# grim_set_config_var

Native target: `grim.dll` at `0x10006580..0x10006b7e` (1534 bytes).

The native function is a sparse `switch` over configuration IDs `5..85`.
Ordinary IDs copy the complete 16-byte `grim_config_value_t` record. The
specialized routes update callback pointers, owned title and resource-pack
strings, input flags, backbuffer state, the D3D texture/blend/filter states,
the gamma ramp, the optional device window, and the render-disable flag.

The ID mapping, early-return policy, string ownership, gamma formula and
clamps, and D3D calls are recovered from the native switch lookup table,
HLIL, and disassembly. The implementation intentionally keeps the logical
C++ method ABI and uses the normal Direct3D 8 interface; it contains no
inline assembly, padding, volatile state, forced registers, dummy
dependencies, or fake references.

Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR-` now produces a `90.12%`
candidate with `438/443` normalized instructions and references `69/1/1`.
The audit identifies the only unresolved/mismatched pair as the compiler's
private sparse-switch lookup and jump tables; all externally meaningful
references resolve. The residual is block placement and shared-tail shaping,
not missing behavior, so the scratch is marked semantic-complete with a
compiler residual.

The available `/GB`, `/G5`, `/G6`, MSVC 6.5, and MSVC 6.5 processor-pack
profiles were checked. `/GB` and `/G5` tie for best; `/G6` and the
processor-pack compiler regress.

## Recorded router-lifetime wave

Live native disassembly shows full scalar record copies in the shared router
tails. `common-copy-tail-mutations.json` evaluated 19 single and pair
spellings. A named config destination followed by four scalar word copies adds
ten candidate instructions and 23.00 fuzzy-weighted bytes, raising the score
from 88.05% to 89.55% without changing the reference audit. The simpler tied
form was retained; the extra source-only value copy was discarded.

The filter route independently exposes native `load current; materialize
config pointer; compare current`. `filter-current-lifetime-mutations.json`
found three byte-identical ways to express that order. The simplest retained
form loads `current` directly before naming the destination pointer. It adds
one instruction, 8.89 fuzzy-weighted bytes, and two resolved references,
bringing the composed result to **90.12%** with a 151.48-byte fuzzy gap.

`resource-path-lifetime-mutations.json` tested four direct-slot and cached
`strdup` call forms against the native import-cache allocation. Three are
byte-neutral and the named-config form regresses, so none was retained. A
five-profile diagnostic matrix likewise keeps stock VC6 `/GB` tied for best;
no compiler override is justified.
