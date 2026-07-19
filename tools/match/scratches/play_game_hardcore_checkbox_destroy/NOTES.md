# `play_game_hardcore_checkbox_destroy`

Live Binary Ninja shows the entire function at `0x0044fa50` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the residual Play Game Hardcore checkbox.
