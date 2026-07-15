# game_completed_typo_button_destroy

Live Binary Ninja shows the entire callback at `0x00406ac0` is one `ret`.
The VC6 relocation beside the function-local Typ'o'Shooter button identifies
it as `$E4`, the empty destructor thunk registered by `atexit`.
