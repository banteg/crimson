# `game_over_highscores_button_destroy`

Live Binary Ninja shows the entire function at `0x004107a0` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the game-over High scores button.
