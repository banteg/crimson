# grim_restore_device_after_activation

`grim_restore_device_after_activation` at `0x100030b0` handles the narrow
window-reactivation reset path. It tests the Direct3D cooperative level,
releases default-pool resources before reset, recreates owned render-target
textures on success, and bounds repeated failures before offering retry or
cancel.

The recovered function matches all 254 native instructions, all 762 bytes, and
all 48 references under MSVC 6.5 `/O2 /GB`.

The two calls at `0x100031ea` and `0x100031f0` both select the one-byte
`grim_noop` body at `0x10001160`, but their native ABI shapes differ. The first
pushes the diagnostic string and zero value; the second pushes only the texture
slot index. `grim_noop_value` models that one-argument no-op role, and the
scratch-local reference alias records the native folding. With fixed
prototypes, VC6 combines the cleanup for the adjacent calls exactly as the
original body does.
