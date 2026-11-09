# grim_init_system

`grim_init_system` is the vtable slot `0x14` method at `0x10005eb0`. Its
low-byte success/failure returns confirm a `bool` ABI.

The method records the current directory, initializes Direct3D, then enables
the configured mouse, keyboard, and joystick devices in that order. Mouse or
keyboard failure tears down the partially initialized window and graphics
state and returns false. Joystick failure is nonfatal: it records the native
misspelled `joystic` error text, disables joystick input, and continues.

On success it initializes and advances the timing state, applies configuration
IDs `0x15` and `0x10`, installs `crimson.paq`, and copies the optional 256-byte
`load\\smallFnt.dat` glyph-width table. Missing font-width data does not fail
initialization.

The config-value wrapper has overloaded implicit constructors: integers write
record word zero and strings write record word three. This is the natural
source shape that makes VC6 construct each 16-byte by-value virtual-call
argument directly on the outgoing stack.

The recovered method matches all 93 native instructions and all 32 references
under MSVC 6.5 `/O2 /GB`.

The freeware DLLs initialize Direct3D and input before checking config flag
66 to skip the splash. 1.0.2 and 1.3.0 clear the screen, fade a centered
128-by-128 quad, and present every frame. The latter counts down at twice
the former's rate. In 1.4.0 the texture and filter setup survive but the
drawing loop is gone. That build also exposes the main-window handle via
config record 82.

The joystick-failure assignment uses a literal false in 1.3.0. Assigning
the failed result instead makes C2 emit a compare against BL in place of
the native AL test. Other builds preserve the failed result.
