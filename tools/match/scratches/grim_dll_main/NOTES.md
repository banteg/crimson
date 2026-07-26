# DllMain

Grim's `DllMain` at `0x10009a20` handles only `DLL_PROCESS_ATTACH`: it caches
the module `HINSTANCE` and loads icon resource `0x72` into
`grim_window_icon_handle`. All reasons return `TRUE`; there is no detach work.

The standard Win32 source matches all ten native instructions and all three
references under MSVC 6.5 `/O2 /GB`.
