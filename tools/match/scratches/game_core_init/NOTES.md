# `game_core_init`

Exact 73-byte, 17-instruction match with MSVC 6.5 `/O2 /GB`; all 12 masked
references align.

Live Binary Ninja shows one caller, `game_startup_init_prelude` at
`0x0042b117`. The coordinator logs startup, initializes quest metadata, effect
defaults, UI assets, and bonus metadata, clears `render_pass_mode`, enters
`GAME_STATE_MAIN_MENU`, logs completion, and returns a byte true value.

Compiling this source as C++ is material. VC6 cleans the first logger arguments
and the `game_state_set` argument together (`add esp, 0x0c`), then cleans the
completion log separately (`add esp, 8`), exactly like the native. C mode
coalesces all five caller-cleaned arguments into one `add esp, 0x14` and misses
one instruction. No barrier or artificial stack manipulation is used.

The Python port constructs these immutable/runtime subsystems through its own
application bootstrap rather than exposing this monolithic coordinator; the
observed initial main-menu state and render-pass clear do not reveal a missing
simulation transition.
