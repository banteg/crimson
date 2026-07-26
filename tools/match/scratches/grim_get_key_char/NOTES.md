# grim_get_key_char

Native target: `grim.dll` at `0x10005c40` (52 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 22/22
normalized instructions, full prefix, and masked references `4/0/0`.

## Recovered source shape

- An empty FIFO returns zero without touching state. Otherwise the method
  snapshots both the current count and oldest character before shifting.
- The do/while loop copies `queue[1..count]` down one slot. The enqueue path
  caps count below 7, so the eight-entry array safely provides the final spare
  element read by this shift.
- After shifting, the method stores the snapshotted count minus one and returns
  the original first entry. Preserving those snapshots materially recovers the
  native EAX/EDX and ESI/EDI schedule.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only control flow is used.
