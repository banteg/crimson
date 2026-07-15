# perk_selection_hover_color_destroy

Live Binary Ninja shows the entire callback at `0x00406160` is one `ret`.
The VC6 relocation adjacent to the function-local hover color identifies it as
`$E3`, the empty destructor thunk registered by `atexit`.
