# grim_shutdown

`grim_shutdown` is the vtable slot `0x18` method at `0x10005ff0`. Live Binary
Ninja evidence and helper xrefs recover the teardown order:

1. Call `grim_lookup_blob_load` with the shared zero-filled
   `grim_empty_string`; its failed-open path frees the optional lookup blob.
2. Shut down mouse, keyboard, and joystick DirectInput ownership.
3. Call `grim_d3d_shutdown`, which releases render surfaces, all texture slots,
   the Direct3D device, and the Direct3D8 interface.
4. Tail-call `grim_window_destroy`.

The straight-line C++ method matches all eight native instructions and all
seven references under MSVC 6.5 `/O2 /GB`.
