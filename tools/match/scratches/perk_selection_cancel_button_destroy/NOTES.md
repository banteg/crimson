# perk_selection_cancel_button_destroy

Live Binary Ninja shows the entire callback at `0x00406140` is one `ret`.
The VC6 relocation adjacent to the function-local Cancel button identifies it
as `$E5`, the empty destructor thunk registered by `atexit`.
