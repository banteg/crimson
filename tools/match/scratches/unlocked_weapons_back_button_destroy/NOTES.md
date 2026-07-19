# `unlocked_weapons_back_button_destroy`

Live Binary Ninja shows the entire function at `0x00440940` is one `ret`.
The native `atexit` registration and object address identify it as the empty
destructor thunk for the unlocked-weapons Back button.
