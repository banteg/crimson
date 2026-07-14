# sfx_entry_table_init

The startup initializer walks all 128 resident SFX slots and invokes the
recovered member-style runtime-state reset on each 0x84-byte entry.
