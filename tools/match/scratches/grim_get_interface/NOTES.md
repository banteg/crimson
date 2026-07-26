# GRIM__GetInterface

The exported `GRIM__GetInterface` factory at `0x100099c0` first probes DirectX
8.1 with `Direct3DCreate8(D3D_SDK_VERSION)`. On failure it stores and displays
the engine's DirectX-install error and returns null. On success it releases the
probe interface, calls the sole 1,872-byte global-default initializer now named
`grim_state_init`, and allocates a four-byte interface object.

The vtable store is recovered as an inlined `GrimInterface` constructor. That
source shape is significant: VC6 emits the native success fallthrough plus an
out-of-line allocation-failure block that explicitly zeroes `EAX`, stores a
null interface instance, and returns. A manual post-allocation vptr assignment
did not reproduce that constructor lowering and was rejected.

The function does not check for an existing instance; it stores the most
recently allocated object. The recovered factory matches all 28 instructions
and all 11 references under MSVC 6.5 `/O2 /GB`.
