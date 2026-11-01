---
tags:
  - reverse-engineering
  - reference
---

# How early Crimsonland changed

The same **Begin game.** button leads to noticeably different games in the surviving freeware builds. The observations below come from the shipped files and the named Windows executable. Addresses are virtual addresses in that release's `crimson.exe`. The [release history](history.md) gives package provenance and dates.

| What the player sees | 1.0.2 | 1.3.0 | 1.4.0 |
| --- | --- | --- | --- |
| Title menu | Six entries, single player, Career and Survival | Seven entries, including local two-player play | Eight entries, including online services |
| Survival | Enemies enter at the midpoint of the right edge | Pairs arrive from opposite sides of the arena | Retains the paired waves |
| Levels | No level pack | Four numbered maps in a hidden Level Test mode | Level code remains, no shipped maps |
| Shotguns | Ten pellets per shot | Twelve pellets from the shotgun, sixteen from the Sewed-off | Twelve pellets from either shotgun |
| Perk draft | Five of sixteen, repeats across levels allowed | Twenty-two registered perks, shared in co-op, with Perk Expert | Adds weapon grants, Fatal Lottery and secret hints |
| Audio | Loose WAV effects, no bundled music | Loose effects and three MP3 tracks | Effects packed into `sounds.paq`, three MP3 tracks |
| Local scores | Name and one score, 36 bytes per entry | Encrypted 56-byte records with a checksum for the table | Retains the richer local score format |
| After a single-player death | Name entry on the next frame, then straight back to the title | Reaper interlude, name entry, then scores | Retains the interlude and scores |

## 1.0.2 — the single-player arena

The six title entries start at (220, 220) in a 640 × 480 window. Career starts with a pistol and 30 rounds. Survival forces the AutoRifle. Its frame loop attempts at most one spawn per frame on a 0.01-second timer. New creatures start at (1024, 512). A nearby creature can prevent a spawn, so the stream thins when enemies bunch up at the entrance. A successful Survival spawn consumes two random numbers, one for heading and one for its 120–129 XP reward. The engine has room for 128 creatures. See the frame dispatcher at `0x40c110`, the arrival branch at `0x40d813` and the spawner at `0x4067a0`.

In relative movement mode, left and right turn the player at two radians per second. Holding both cancels the turn. Left Ctrl snaps the crosshair 60 units in front of the player. The left mouse button, right Ctrl and Enter fire. The frame keeps the crosshair half a player-width inside the screen. It draws the ground with the previous frame’s camera before centering the creatures and player with the new camera. See `0x408040` for movement and `0x40c243` for the ground draw.

Creatures face their pursuit direction immediately. Even a creature with zero pursuit speed drifts as its attack timer runs. Plague deals 5 damage per tick and a lethal tick credits XP directly. In the credits, holding Space returns the scroll to the beginning. The original draws 46 text lines per frame, including fourteen named beta testers. See the credits at `0x40eda0`.

An enemy killed in Career can leave one of four pickup types. A weapon pickup chooses its weapon at collection. It draws from IDs 1–8 and rerolls from 1–7 if the first draw equals the current weapon. Taking a pistol this way gives 15 rounds. See the drop at `0x40314d` and the collection at `0x40772e`.

The early shotgun fires ten pellets. The twin plasma rifle fires two bolts, eighteen degrees to either side of the crosshair, for two rounds of ammo. A plasma rifle bolt does 9.6 times the base bullet damage. All weapons take 1.5 seconds to reload, or 0.95 seconds with Fastloader. The firing switch includes an additional ID 17 that launches a delayed particle burst. The HUD displays it as `Unknown`. See `0x408e0d` for firing, `0x402f3d` for damage and `0x40e235` for the HUD names.

Career registers sixteen perks, starting with Bloody Mess at ID 0 and ending with Jinxed at ID 15. Each draft draws five distinct IDs from the whole table. It can offer a perk the player already owns. **Timebender** slows play while the right mouse button or Space is held and spends XP each frame. Survival enables the same control without acquiring the perk. **Jinxed** checks one creature slot every 0.6 game seconds. Career's first level-up requires 3,250 XP. Registration, drafting and the time control are at `0x401c80`, `0x402900` and `0x408366`.

The packaged Career scoreboard contains a record for `10tons` with 28,930 XP. A record has a 32-byte name followed by a little-endian integer. The integer is XP in Career and elapsed seconds in Survival. The writer and reader are at `0x401940` and `0x401a40`.

## 1.3.0 — co-op and authored levels

The title offers a second player. Survival's spawn interval becomes 0.25 seconds divided by the player count. The two entry positions oscillate on opposite sides. The pool grows to 512 creatures, with ordinary Survival rewards of 140–169 XP. Compare the paired arrivals at `0x416fa9` and the individual spawn at `0x40ba70` with the earlier addresses above.

The player’s turn rate now ramps up. The three aiming options are mouse, keyboard and joystick hat. A fire-key press snaps non-mouse aim. Creatures turn toward a target heading, can switch targets when their co-op target dies, and use an eight-unit radius for wall collisions. Plague damage rises to 15 and a lethal tick runs the usual creature-death handler. The credits at `0x4183f0` scroll faster, thank the Pelit.fi and MuroPaketti forums, and draw 57 lines per frame with twenty named beta testers.

At the title screen, hold **left Ctrl** and type **LEVELS**, then cycle the game mode to **Level Test**. The key sequence is in the dispatcher at `0x4145b3`. Four numbered maps cycle in order. The ZIP also carries three other map files and a separate `tiles.paq`. Level Test can place creatures that wait for the player to approach and triggers that grant a weapon. Its spawner gives placed creatures 300 health instead of scaling health with elapsed time.

After the last creature retires, the level-clear screen stays up for three game seconds. The dispatcher then loads the next numbered map. The fourth clear returns to level one. Death takes a different path. The reaper interlude advances the simulation clock twice per frame while creature and projectile updates are suspended, then opens name entry.

Walls affect gunfire as well as movement. A normal bullet stops when it hits a wall. When `rand() % 15 == 2`, the impact also spawns a pistol projectile at a right angle. The wall query and impact branch are at `0x40642c` and `0x406d94`.

The armory now has seventeen named entries. The twin plasma rifle gives way to the TriPlasma Rifle, which fires a center bolt alongside the two angled bolts for one round of ammo. Reload time depends on the weapon, from 1.2 seconds for a pistol to 5.1 seconds for the Mean Minigun. The Plague Gun fires an infectious round. ID 16, displayed as **The Secret Weapon**, has a one-round clip and consumes ammo without emitting a projectile in the firing switch. See `0x403c00` for clips, `0x403e00` for reloading and `0x40e430` for firing.

The 22-entry perk table drops Timebender and adds choices including Lean Mean Exp Machine, Evil Eye, Final Revenge, Infernal Contract and Perk Expert. The normal picker rolls IDs 1–21, so it skips Bloody Mess at slot 0. It avoids owned perks while alternatives are available. Co-op also filters out Grim Deal, Final Revenge and Infernal Contract. Perk Expert adds two slots per stack. Accepting a selection copies the first player's perk counts to the second player. See `0x404ad0`, `0x405bb0` and `0x4114e5`.

The score writer at `0x404510` saves the name, time, XP, frame-rate statistics and game version. The writer rejects a run below 15 average FPS. The encoder at `0x4043d0` protects the record table. A single checksum follows all records in the file.

### Can you get the two hidden weapons in 1.3.0?

The readme counts two hidden weapons. Neither **The Secret Weapon** (16) nor the **Plague Gun** (17) has a grant in ordinary play with the shipped files. The executable does equip both when an authored level asks for them.

- **Career and Survival.** The only writer of the pickup's weapon ID (`0x4477fc`) rolls `2 + rand() % 14` and retries if the player already has that weapon. Collection passes that value to the equip routine at `0x40cba6`. Apart from the equip routine, the writes to the players’ weapon fields give them a pistol on reset or level entry, or an AutoRifle in Survival. The single-player death branch at `0x4161f3` goes to the death screen even at 6, 66, 666 or 6,666 XP.
- **Level Test.** The other call to the equip routine is at `0x402196`. A type-2 trigger gives the player the weapon stored at offset `0x20` in its record. Levels 2 and 3 each grant weapon 2, the AutoRifle. Levels 1 and 4 have no weapon trigger. After level 4, the loader at `0x411610` tries `levels/level_5.lvl` and falls back to level 1. It never selects the three named maps bundled alongside them. The menu caps the mode at Level Test (`0x41610b`). Even the unused editor writes weapon 2 into new weapon triggers (`0x413c3b`).
- **Authored map.** To reproduce the grant, copy the shipped `level_2.lvl` to `levels/level_5.lvl`. At file offset `0x3a1`, change the little-endian weapon ID from 2 to 16 or 17. In that fifth level, move within 20 units of the trigger at approximately (837, 413). The original and both clients equip ID 16 with one round or ID 17 with twenty. Standing exactly on the radius does nothing, and the spent trigger does not refill the weapon.

## 1.3.1 and 1.4.0 — back to the arena

The 1.3.1 and 1.4.0 readmes describe levels as disabled. Neither ships the 1.3.0 maps. 1.3.1 is a comparison build in this project. Its shared art and combat code help distinguish features that already existed before the final freeware release. The 1.4.0 title exposes online services alongside the local game modes.

1.3.1 is the first preserved build with the Plague Gun resurrection. In single-player, a lethal hit at exactly 6, 66, 666 or 6,666 XP grants weapon 17 and restores 1 HP while the revive timer is below 1. The checks are at `0x41b7d0` in 1.3.1 and `0x41be7e` in 1.4.0. At 667 XP both enter the death screen. In 1.0.2 (`0x40de74`) and 1.3.0, all five XP values give an ordinary death.

## What the clients reproduce

The early clients load each edition's own artwork, font and sounds, and implement its title choices, Survival arrivals and score format. The 1.3.0 client also loads the shipped numbered maps.

The weapon and perk regression runs each original executable against the native and WebAssembly game code. It compares fired projectiles, ammo, reloads, hits, perk text, draft RNG, grants and level-up rewards. The historical compiler reproduces the complete machine-code body of the perk draft in each executable (22 instructions in 1.0.2, 65 in 1.3.0), all 51 instructions of the 1.3.0 reload routine and the random Career creature spawner in all three playable releases.

The acquisition checks run the 1.3.0 pickup generator and collection code, then load the numbered maps through the original level reader. Native and browser runs compare weapon, ammo, trigger state and pickup RNG against that executable. The death checks compare health, weapon and game state in both early releases.

The frame checks call each early executable’s frame dispatcher from entry to return. They compare gameplay state, camera and ground position, cursor, health, XP, ammo, creature and projectile activity, and the final random state on each frame. The 1.3.0 level checks load each shipped map and seed its final encounter, then follow the kill, corpse retirement, level-clear screen and next load through the full four-map cycle. Separate checks compare player and creature movement, damage on contact, the credits draw calls and the contents of a saturated corpse queue. The early releases still need complete HUD and world-effect draw comparisons.
