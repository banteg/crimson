# game_completed_main_menu_button_destroy

Live Binary Ninja shows the entire callback at `0x00406ab0` is one `ret`.
The VC6 relocation beside the function-local Main Menu button identifies it as
`$E5`, the empty destructor thunk registered by `atexit`.
