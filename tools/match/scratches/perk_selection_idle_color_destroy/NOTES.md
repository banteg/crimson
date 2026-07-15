# perk_selection_idle_color_destroy

Live Binary Ninja shows the entire callback at `0x00406170` is one `ret`.
The VC6 relocation adjacent to the function-local idle color identifies it as
`$E2`, the empty destructor thunk registered by `atexit`.
