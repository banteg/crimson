# perk_selection_select_button_destroy

Live Binary Ninja shows the entire callback at `0x00406130` is one `ret`.
The VC6 relocation adjacent to the function-local Select button identifies it
as `$E6`, the empty destructor thunk registered by `atexit`.
