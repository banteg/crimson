# `config_sync_from_grim`

Native target: `crimsonland.exe` at `0x0041ec60` (1225 bytes).

Live Binary Ninja evidence recovers the complete Grim-to-game configuration
bridge. The function reads windowed mode, display depth and dimensions, texture
scale, and the safe-mode flag through `grim_get_config_var`; mirrors the active
high-score name into the persistent `0x480`-byte config blob; and rewrites
`crimson.cfg`.

When Grim's configuration dialog was invoked, the function constructs a local
legacy-default blob, optionally replaces it with an exact-size file read, and
imports only its short player-name buffer and violence flag before writing the
live global blob. The local initializer establishes the 800x600 fullscreen
migration defaults, eight `"default"` saved-name slots, the `"10tons"` profile,
both players' key bindings, detail/audio settings, and POV directions. An
indexed saved-name loop naturally produces the native pair of strength-reduced
induction cursors.

The store at `config_windowed` is byte-sized and the function returns `true` in
`AL`, leaving the upper return bytes as ordinary call residue. Those facts
correct the earlier four-byte field and `int` return guesses. Natural VC6
`/O2 /GB` code matches all 277 instructions and references `37/0/0`; the source
passes the fakematch validator without coercion or dead expressions.
