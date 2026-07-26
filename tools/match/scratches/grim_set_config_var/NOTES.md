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

Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR-` produces an `88.05%`
candidate with `427/443` normalized instructions and references `67/1/1`.
The audit identifies the only unresolved/mismatched pair as the compiler's
private sparse-switch lookup and jump tables; all externally meaningful
references resolve. The residual is block placement and shared-tail shaping,
not missing behavior, so the scratch is marked semantic-complete with a
compiler residual.

The available `/GB`, `/G5`, `/G6`, MSVC 6.5, and MSVC 6.5 processor-pack
profiles were checked. `/GB` and `/G5` tie for best; `/G6` and the
processor-pack compiler regress.
