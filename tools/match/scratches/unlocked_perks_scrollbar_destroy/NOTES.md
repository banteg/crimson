# `unlocked_perks_scrollbar_destroy`

Live Binary Ninja shows the entire function at `0x00441190` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the unlocked-perks scroll-list state.
