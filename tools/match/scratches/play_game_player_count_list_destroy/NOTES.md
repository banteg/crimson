# `play_game_player_count_list_destroy`

Live Binary Ninja shows the entire function at `0x0044fa30` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the Play Game player-count list.
