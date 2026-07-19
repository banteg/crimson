# `unlocked_weapons_scrollbar_destroy`

Live Binary Ninja shows the entire function at `0x00440950` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the unlocked-weapons scroll-list state.
