# `play_game_tutorial_button_destroy`

Live Binary Ninja shows the entire function at `0x0044fa40` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the Play Game Tutorial button.
