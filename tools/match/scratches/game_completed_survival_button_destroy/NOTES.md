# game_completed_survival_button_destroy

Live Binary Ninja shows the entire callback at `0x00406ae0` is one `ret`.
The VC6 relocation beside the function-local Survival button identifies it as
`$E2`, the empty destructor thunk registered by `atexit`.
