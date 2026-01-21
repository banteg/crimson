---
tags:
  - status-draft
---

# Weapon ID map

**Source:** `weapon_table_init` (`FUN_004519b0`) copies weapon display names into
`weapon_table` entries. Weapon ids index the table as
`weapon_table + weapon_id * 0x1f` (stride `0x7c`).

Notes:

- Weapon ids are **1-based** in code. Id `0` is a dummy/none entry
  (entry 0 has ammo class `-1`).

- Some weapon name strings are stored at offsets that Ghidra’s string extractor
  truncates (e.g., 0x0047956c → **Shotgun**, 0x004793f4 → **RayGun**,
  0x0047933a + 2 → **Lighting Rifle**). These are resolved by reading the
  executable bytes at the exact address, matching the `weapon_table_init` copies.

- IDs 34–40 and 46–49 are left **Unknown / unlabelled** because
  `weapon_table_init` never copies a name into those entries and there are no
  direct callsite references to those ids. They are likely unused/reserved.

## IDs

| ID (dec) | ID (hex) | Name |
| --- | --- | --- |
| 0 | 0x00 | None (dummy entry) |
| 1 | 0x01 | Pistol |
| 2 | 0x02 | Assault Rifle |
| 3 | 0x03 | Shotgun |
| 4 | 0x04 | Sawed-off Shotgun |
| 5 | 0x05 | Submachine Gun |
| 6 | 0x06 | Gauss Gun |
| 7 | 0x07 | Mean Minigun |
| 8 | 0x08 | Flamethrower |
| 9 | 0x09 | Plasma Rifle |
| 10 | 0x0a | Multi-Plasma |
| 11 | 0x0b | Plasma Minigun |
| 12 | 0x0c | Rocket Launcher |
| 13 | 0x0d | Seeker Rockets |
| 14 | 0x0e | Plasma Shotgun |
| 15 | 0x0f | Blow Torch |
| 16 | 0x10 | HR Flamer |
| 17 | 0x11 | Mini-Rocket Swarmers |
| 18 | 0x12 | Rocket Minigun |
| 19 | 0x13 | Pulse Gun |
| 20 | 0x14 | Jackhammer |
| 21 | 0x15 | Ion Rifle |
| 22 | 0x16 | Ion Minigun |
| 23 | 0x17 | Ion Cannon |
| 24 | 0x18 | Shrinkifier 5k |
| 25 | 0x19 | Blade Gun |
| 26 | 0x1a | Spider Plasma |
| 27 | 0x1b | Evil Scythe |
| 28 | 0x1c | Plasma Cannon |
| 29 | 0x1d | Splitter Gun |
| 30 | 0x1e | Gauss Shotgun |
| 31 | 0x1f | Ion Shotgun |
| 32 | 0x20 | Flameburst |
| 33 | 0x21 | RayGun |
| 34 | 0x22 | Unknown / unlabelled |
| 35 | 0x23 | Unknown / unlabelled |
| 36 | 0x24 | Unknown / unlabelled |
| 37 | 0x25 | Unknown / unlabelled |
| 38 | 0x26 | Unknown / unlabelled |
| 39 | 0x27 | Unknown / unlabelled |
| 40 | 0x28 | Unknown / unlabelled |
| 41 | 0x29 | Plague Sphreader Gun |
| 42 | 0x2a | Bubblegun |
| 43 | 0x2b | Rainbow Gun |
| 44 | 0x2c | Grim Weapon |
| 45 | 0x2d | Fire bullets |
| 46 | 0x2e | Unknown / unlabelled |
| 47 | 0x2f | Unknown / unlabelled |
| 48 | 0x30 | Unknown / unlabelled |
| 49 | 0x31 | Unknown / unlabelled |
| 50 | 0x32 | Transmutator |
| 51 | 0x33 | Blaster R-300 |
| 52 | 0x34 | Lighting Rifle |
| 53 | 0x35 | Nuke Launcher |
