# `game_over_name_input_state_destroy`

Live Binary Ninja shows the entire function at `0x004107c0` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the game-over name-input state.
