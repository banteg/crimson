# grim_app_init

`grim_app_init` at `0x10002fc0` initializes the `MyApp` runtime object before
the Win32 message loop. It resets the timer and object handles, captures the
client dimensions, applies the configured backbuffer size, records the current
working directory, and publishes the client rectangle.

The client rectangle is a native 16-byte overlay: Win32 fills it as a `RECT`,
then the initializer clears the low-byte enabled field before copying the whole
record. This explains the otherwise odd byte store over `RECT.left`.

The recovered method matches all 54 native instructions and all 13 references
under MSVC 6.5 `/O2 /GB`.
