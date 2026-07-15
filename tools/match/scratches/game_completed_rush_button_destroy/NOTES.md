# game_completed_rush_button_destroy

Live Binary Ninja shows the entire callback at `0x00406ad0` is one `ret`.
The VC6 relocation beside the function-local Rush button identifies it as
`$E3`, the empty destructor thunk registered by `atexit`.
