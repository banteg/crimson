# grim_flush_input

Native target: `grim.dll` at `0x10007330` (91 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 34/34
normalized instructions, full prefix, and masked references `5/0/0`.

## Recovered source shape

- The method clears the 256-byte keyboard state before touching the buffered
  event queue.
- A single count initialized to 10 is passed to DirectInput `GetDeviceData`.
  The method keeps draining while the returned unsigned count is nonzero, with
  the post-incremented retry guard allowing at most 101 calls.
- The native object-size argument is 20 bytes, matching DirectInput8's
  five-dword `DIDEVICEOBJECTDATA` layout including `uAppData`.
- After draining, the method clears the keyboard state again and empties the
  separate key-char FIFO. The clean source writes the FIFO count after the
  second `memset`; MSVC safely schedules that independent store before the
  native `rep stosd`.
- The calibrated compiler's bundled DirectInput header predates version 8, so
  the scratch declares only the documented 32-bit event layout and COM vtable
  prefix needed for `GetDeviceData` at slot `0x28`.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only control flow is used.
