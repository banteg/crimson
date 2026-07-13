# grim_mouse_init

Native target: `grim.dll` at `0x1000a5a0..0x1000a662` (194 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 71/71
normalized instructions, full prefix, and masked references `18/0/0`.

## Recovered source shape

- The function snapshots `grim_main_window_hwnd`. If both it and
  `GetForegroundWindow` are null, `GetDesktopWindow` is called but its return
  value is intentionally ignored; the saved window remains unchanged.
- It lazily creates the DirectInput8 interface with version `0x800` and
  `IID_IDirectInput8A`. Failure clears the interface global and returns false.
- It lazily creates the device with `GUID_SysMouse`, installs
  `c_dfDIMouse2`, and sets cooperative flags 5. Failure at any of those three
  steps returns false.
- A newly configured non-null device is acquired, then `grim_mouse_poll` is
  called. Both results are ignored and the initializer returns true.
- The bundled VC6 SDK predates DirectInput8, so the scratch declares only the
  truthful DX8 COM prefixes used here. The slots retain native offsets
  `0x0c`, `0x1c`, `0x2c`, and `0x34` and their x86 `__stdcall` ABI.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only control flow is used.
