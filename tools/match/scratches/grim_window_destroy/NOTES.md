# grim_window_destroy

`grim_window_destroy` at `0x10002880` posts `WM_QUIT`, conditionally destroys
the main window, unregisters the window class, and returns the
`UnregisterClassA` result.

The native body contains a second independent branch: when
`grim_device_window_override` is non-null, it calls `DestroyWindow` with
`grim_main_window_hwnd` again, not with the override handle. This exact source
shape matches the binary and is preserved as an apparent original bug rather
than rewritten into the behavior the names might suggest.

The recovered function matches all 22 native instructions and all eight
references under MSVC 6.5 `/O2 /GB`.
