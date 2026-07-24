# `player_state_table_global_init`

Native target: `crimsonland.exe` at `0x0041e5d0` (227 bytes).

The CRT initializer constructs both 0x360-byte player states. Its first ten
stores reproduce the same 0x98-byte entity-prefix defaults used by the creature
pool constructor. The remaining stores initialize player timers, weapon state,
auto-target fields, a `(-1,-1)` movement target, and the default level/clip.

Keeping the shared prefix initialization in an inline member boundary is
required for VC6 to reproduce all 50 native instructions: flattening the same
stores hoists the first move-target component across that boundary. The native
header now exposes the proven entity fields instead of treating the first 16
bytes and the constructor-touched offsets `0x38`, `0x74`, `0x78`, `0x90`, and
`0x98` as anonymous padding.

Offset `0x98` is now typed as `float`: the constructor writes floating zero
bits, and `player_render_overlays` is its only recovered read, through an x87
load compared with `0.25f`. Its reserved name remains until a writer or
stronger gameplay role is recovered.
