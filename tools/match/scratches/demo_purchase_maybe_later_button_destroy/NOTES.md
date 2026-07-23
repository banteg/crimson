# `demo_purchase_maybe_later_button_destroy`

Exact one-byte `ret` thunk at `0x0040c1b0`. Live Binary Ninja disassembly and
the `demo_purchase_screen_update` constructor block identify it as the atexit
destructor registered for the function-local Maybe later button.
