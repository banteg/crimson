# `play_game_quests_button_destroy`

Live Binary Ninja shows the entire function at `0x0044fa90` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the Play Game Quests button.
