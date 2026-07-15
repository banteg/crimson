# bonus_meta_entry_init

Native target: `crimsonland.exe` at `0x004123f0` (27 bytes).

The natural constructor clears both owned strings and the enabled flag, uses
icon sentinel -1, and seeds the default amount to one.

It matches all eight native instructions, full prefix, with no references.
