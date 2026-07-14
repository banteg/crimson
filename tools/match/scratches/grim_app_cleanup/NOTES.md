# grim_app_cleanup

`grim_app_cleanup` at `0x10002f60` releases the `MyApp` GDI object at offset
`0x1c` and clears the member. Its `0x10003080` thunk is the cleanup call made
when the Grim message loop exits.

The recovered method matches all 10 native instructions and its
`DeleteObject` reference under MSVC 6.5 `/O2 /GB`.
