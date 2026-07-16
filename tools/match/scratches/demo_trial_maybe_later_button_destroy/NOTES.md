# demo_trial_maybe_later_button_destroy

Live Binary Ninja shows the entire callback at `0x00405150` is one `ret`.
The VC6 relocation beside the function-local Maybe later button identifies it
as `$E2`, the empty destructor thunk registered by `atexit`.
