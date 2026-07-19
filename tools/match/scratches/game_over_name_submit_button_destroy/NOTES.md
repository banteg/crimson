# `game_over_name_submit_button_destroy`

Live Binary Ninja shows the entire function at `0x004107d0` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the game-over name-submit button.
