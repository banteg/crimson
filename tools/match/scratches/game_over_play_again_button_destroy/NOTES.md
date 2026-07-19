# `game_over_play_again_button_destroy`

Live Binary Ninja shows the entire function at `0x004107b0` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the game-over Play Again button.
