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

Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR-` now produces a `94.36%`
candidate with `443/443` normalized instructions and references `68/1/1`.
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

## Shared record-copy tail

Raw native disassembly at `0x100065b3..0x100065e8` and
`0x10006b42..0x10006b7e` shows that texture-stage configuration ID 26
publishes word zero and then joins the ordinary router's word-one-through-three
tail. `shared-copy-tail-mutations.json` evaluated all 24 singles and pairs
across that entry and the common destination. Eight natural two-site forms
compile identically and improve the baseline.

The retained negative-test form mirrors the native failure branch, stores word
zero, and enters an explicit shared tail. It adds five previously missing
instructions, **64.92 fuzzy-weighted bytes**, and three exact prefix
instructions. The result is **94.36%**, with an **86.57-byte fuzzy gap**,
exactly **443/443 instructions**, prefix **7/443**, and references
**68/1/1**.

Four follow-up searches bound the remaining local residual. Replaying the
resource-path lifetime menu is byte-neutral. Explicitly spelling the proven
case-16 index before the intervening resource lookup removes three
instructions and regresses by 19.40 weighted bytes. Six scalar source-load
orders and six destination pointer/reference shapes either collapse to the
retained object or regress. The native DLL's imported `_strdup` also motivated
an ABI-profile check: `/MD` reproduces dynamic-CRT call lowering but scores
93.57%, below the canonical `/GB` result, so no flag override is retained.

Two recorded import-spelling matrices test the native case-16 `_strdup`
pointer lifetime directly. `strdup-import-lifetime-mutations.json` evaluates
five declaration and call spellings: the `_strdup` spelling is byte-neutral,
while explicit `dllimport` redeclarations conflict with the CRT headers and
fail compilation. Its SHA-256 is
`f8b49fba0c91e2dd06b3b45e6ed447e6048df96a05514a9850cc62a314c55e4f`.

`strdup-iat-symbol-mutations.json` evaluates three explicit IAT-symbol
combinations. The pointer declaration alone is byte-neutral; routing both
calls through it compiles but regresses by 6.93 fuzzy-weighted bytes, and the
call-only partial form fails compilation. The native import-pointer hoist
cannot be recovered through an honest source-level declaration under the
current CRT headers, so no import spelling is retained. The plan SHA-256 is
`147c5fe7379f0cc416f334900cdb9c37e81ff6002d01909c1c32304571611061`.
