# quest_meta_entry_release

Native target: `crimsonland.exe` at `0x004121e0` (15 bytes).

The natural destructor conditionally releases the heap-owned quest name.

It matches all seven native instructions, full prefix, with the release
reference aligned.
