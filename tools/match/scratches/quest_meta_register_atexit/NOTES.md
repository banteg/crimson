# quest_meta_register_atexit

Native target: `crimsonland.exe` at `0x004121f0` (12 bytes).

This helper registers the quest metadata array destructor with the static CRT.

It matches all four native instructions, full prefix, with both references
aligned; the CRT result is intentionally discarded.
