# perk_selection_choice_items_destroy

Live Binary Ninja shows the entire callback at `0x00406150` is one `ret`.
The VC6 relocation adjacent to the ten-item local-static array identifies it as
`$E4`, the empty array-destructor thunk registered by `atexit`.
