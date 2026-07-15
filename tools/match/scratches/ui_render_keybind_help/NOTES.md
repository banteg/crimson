# `ui_render_keybind_help`

Native target: `crimsonland.exe` at `0x00405160` (1142 bytes).

Live Binary Ninja body and sole-callsite evidence recovers the pause key-info
panel: a translucent 512x256 frame, mono title, global Level Up and Reload
bindings, two five-row player binding columns, and the F1 return hint.

Exact verified match: 100.00%, with 324/324 normalized instructions and masked
references `80/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

## Recovered source shape

- The panel position is a value copy of the caller's two-float vector before
  the 32/50-pixel content offsets are applied. This explains the native pair
  of integer-width member copies.
- The title uses the variadic mono formatter at vtable slot `0x140`, even
  though the literal has no formatting directives.
- Each player column walks five consecutive integers from
  `config_blob.keybinds_p1` using `player * 5` as its base. Consequently, the
  second column reads slots 5 through 9 of that block rather than the distinct
  `keybinds_p2` block. This surprising layout is native behavior, not a port
  correction.
- Naming the final binding `fire_key` lets VC6 naturally reuse the dead index
  register before the nested key-name/virtual-format calls. No register or
  ordering constraint is present in the source.

The source uses no inline assembly, volatile state, dummy references, dead
expressions, or artificial ordering constraints. The fakematch validator
passes.
