# Weapon ID map

**Source:** `weapon_table_init` (`FUN_004519b0`) copies weapon display names into
`weapon_table` entries. Weapon ids index the table as
`weapon_table + weapon_id * 0x1f` (stride `0x7c`).

Notes:
- `weapon_id = -1` is effectively “none” (entry 0 is a dummy with ammo class `-1`).
- Some weapon name strings are stored at offsets that Ghidra’s string extractor
  truncates (e.g., 0x0047956c → **Shotgun**, 0x004793f4 → **RayGun**,
  0x0047933a + 2 → **Lighting Rifle**). These are resolved by reading the
  executable bytes at the exact address, matching the `weapon_table_init` copies.
- IDs 33–39 and 45–48 are left **Unknown / unlabelled** because
  `weapon_table_init` never copies a name into those entries and there are no
  direct callsite references to those ids. They are likely unused/reserved.

## IDs

| ID (dec) | ID (hex) | Name |
| --- | --- | --- |
| 0 | 0x00 | Pistol |
| 1 | 0x01 | Assault Rifle |
| 2 | 0x02 | Shotgun |
| 3 | 0x03 | Sawed-off Shotgun |
| 4 | 0x04 | Submachine Gun |
| 5 | 0x05 | Gauss Gun |
| 6 | 0x06 | Mean Minigun |
| 7 | 0x07 | Flamethrower |
| 8 | 0x08 | Plasma Rifle |
| 9 | 0x09 | Multi-Plasma |
| 10 | 0x0a | Plasma Minigun |
| 11 | 0x0b | Rocket Launcher |
| 12 | 0x0c | Seeker Rockets |
| 13 | 0x0d | Plasma Shotgun |
| 14 | 0x0e | Blow Torch |
| 15 | 0x0f | HR Flamer |
| 16 | 0x10 | Mini-Rocket Swarmers |
| 17 | 0x11 | Rocket Minigun |
| 18 | 0x12 | Pulse Gun |
| 19 | 0x13 | Jackhammer |
| 20 | 0x14 | Ion Rifle |
| 21 | 0x15 | Ion Minigun |
| 22 | 0x16 | Ion Cannon |
| 23 | 0x17 | Shrinkifier 5k |
| 24 | 0x18 | Blade Gun |
| 25 | 0x19 | Spider Plasma |
| 26 | 0x1a | Evil Scythe |
| 27 | 0x1b | Plasma Cannon |
| 28 | 0x1c | Splitter Gun |
| 29 | 0x1d | Gauss Shotgun |
| 30 | 0x1e | Ion Shotgun |
| 31 | 0x1f | Flameburst |
| 32 | 0x20 | RayGun |
| 33 | 0x21 | Unknown / unlabelled |
| 34 | 0x22 | Unknown / unlabelled |
| 35 | 0x23 | Unknown / unlabelled |
| 36 | 0x24 | Unknown / unlabelled |
| 37 | 0x25 | Unknown / unlabelled |
| 38 | 0x26 | Unknown / unlabelled |
| 39 | 0x27 | Unknown / unlabelled |
| 40 | 0x28 | Plague Sphreader Gun |
| 41 | 0x29 | Bubblegun |
| 42 | 0x2a | Rainbow Gun |
| 43 | 0x2b | Grim Weapon |
| 44 | 0x2c | Fire bullets |
| 45 | 0x2d | Unknown / unlabelled |
| 46 | 0x2e | Unknown / unlabelled |
| 47 | 0x2f | Unknown / unlabelled |
| 48 | 0x30 | Unknown / unlabelled |
| 49 | 0x31 | Transmutator |
| 50 | 0x32 | Blaster R-300 |
| 51 | 0x33 | Lighting Rifle |
| 52 | 0x34 | Nuke Launcher |
