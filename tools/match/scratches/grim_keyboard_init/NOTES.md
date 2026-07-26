# grim_keyboard_init

Native target: `grim.dll` at `0x1000a390..0x1000a4a0` (272 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 89/89
normalized instructions, full prefix, and masked references `18/0/0`.

## Recovered source shape

- A null `hwnd` triggers a foreground-window query. If that is also null,
  `GetDesktopWindow` is called, but its return value is intentionally ignored;
  the original argument is still used later.
- The DirectInput8 interface is created lazily with version `0x800` and
  `IID_IDirectInput8A`. Failure clears the interface global and returns false.
- The keyboard device is also created lazily with `GUID_SysKeyboard`. The
  function installs `c_dfDIKeyboard`, then cooperative flags `0x16`; each of
  those three HRESULT failures returns false.
- A 20-byte DirectInput dword property sets buffer size 10 at device scope.
  The property HRESULT is ignored. A newly created device is acquired if it
  remains non-null.
- The function always calls `grim_keyboard_poll` on the success/existing-device
  path and returns true without propagating the poll result.
- The bundled VC6 SDK predates DirectInput8, so the scratch declares the real
  DX8 COM prefixes and property layout used by this function. All slots retain
  their native offsets and `__stdcall` ABI; no fabricated methods are called.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only control flow is used.
