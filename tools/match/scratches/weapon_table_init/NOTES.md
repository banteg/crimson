# `weapon_table_init`

Native target: `crimsonland.exe` at `0x004519b0` (4885 bytes).

Live Binary Ninja evidence recovers the complete 64-slot native weapon-table
initializer. The underlying row begins with the ammo class at `0x004d7a28`;
the public name/table view starts four bytes later at `0x004d7a2c`, and rows
have a `0x7c`-byte stride. The initial loop assigns `hud_icon_id = id - 1`
and `pellet_count = 1` to every slot, including unnamed slots, before restoring
the dummy row's icon to zero.

The source preserves all 42 native display names and their original order,
including `Fire bullets`, `Plague Sphreader Gun`, and `Lighting Rifle`. It also
recovers clip, timing, spread, ammo-class, SFX, flag, icon, pellet, travel, and
damage overrides, plus the shared storage aliases used by the Fire Bullets
fallback and SFX-anchor paths. The initializer writes the flags field as a
32-bit value; the prior byte-oriented analysis view describes consumer usage
but not the native construction type.

The apparently interleaved string and metadata stores are VC6 scheduling of
ordinary inline `strcpy` operations and adjacent per-weapon assignment blocks.
No disassembly-shaped copies or synthetic references are used.

Verified with MSVC 6.5 `/O2 /GB`: 1000/1000 instructions, 4885 bytes, and all
477 masked references audited.

The complete initializer now uses the canonical `weapon_storage_entry_t`
instead of privately redeclaring the ammo-class-first 0x7c row. The data map
types `weapon_ammo_class` as the corresponding 64-row storage array while
retaining the overlapping public `weapon_stats_t[64]` symbol four bytes later.
This source/type recovery is byte-neutral: 1000/1000 instructions and all 477
references remain exact.
