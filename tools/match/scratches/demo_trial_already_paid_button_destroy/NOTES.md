# demo_trial_already_paid_button_destroy

Live Binary Ninja shows the entire callback at `0x00405130` is one `ret`.
The VC6 relocation beside the function-local Already paid button identifies it
as `$E4`, the empty destructor thunk registered by `atexit`.
