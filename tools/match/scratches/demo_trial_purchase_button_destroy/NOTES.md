# demo_trial_purchase_button_destroy

Live Binary Ninja shows the entire callback at `0x00405140` is one `ret`.
The VC6 relocation beside the function-local Purchase button identifies it as
`$E3`, the empty destructor thunk registered by `atexit`.
