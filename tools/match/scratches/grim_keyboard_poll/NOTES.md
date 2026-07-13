# grim_keyboard_poll

Native target: `grim.dll` at `0x1000a4a0..0x1000a545` (165 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 60/60
normalized instructions, full prefix, and masked references `9/0/0`.
The same source reaches 98.33% with `msvc6.5pp` and 77.69% with `msvc7.0`,
so the exact stock VC6 result is compiler-profile evidence rather than a loose
semantic match.

## Recovered source shape

- A null keyboard device returns false. Otherwise `Acquire` is retried without
  a bound for `DIERR_INPUTLOST` and `DIERR_NOTACQUIRED`; any other failed
  acquisition returns false.
- On success the function clears the 256-byte keyboard state and calls
  `GetDeviceState`. Its HRESULT is intentionally ignored.
- `GetDeviceData` receives ten 20-byte `DIDEVICEOBJECTDATA`-shaped entries.
  The local count is intentionally signed because the native loop uses a
  signed `jle`; its pointer remains x86 ABI-compatible with DirectInput's
  `DWORD *` parameter.
- A successful data call applies every returned event as
  `state[event.dwOfs] = (unsigned char)event.dwData`. Native code neither
  clamps the returned count nor bounds-checks the offset. A failed data call
  skips the event loop but still returns true.
- The poll only refreshes keyboard state. It does not touch the key-character
  FIFO or key-repeat timers. The byte-sized `bool` return reproduces the
  native `al` writes, unlike the prior decompiler-level `int` declaration.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only control flow is used.
