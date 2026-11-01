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
| Audio | Loose WAV effects, no bundled music | Loose effects and three MP3 tracks | Effects packed into `sounds.paq`, three MP3 tracks |
| Local scores | Name and one score, 36 bytes per entry | Encrypted 56-byte records with a checksum for the table | Retains the richer local score format |

## 1.0.2 — the single-player arena

The six title entries start at (220, 220) in a 640 × 480 window. Career starts with a pistol and 30 rounds. Survival forces the AutoRifle. Its frame loop attempts at most one spawn per frame on a 0.01-second timer. New creatures start at (1024, 512). A nearby creature can prevent a spawn, so the stream thins when enemies bunch up at the entrance. A successful Survival spawn consumes two random numbers, one for heading and one for its 120–129 XP reward. The engine has room for 128 creatures. See the frame dispatcher at `0x40c110`, the arrival branch at `0x40d813` and the spawner at `0x4067a0`.

The packaged Career scoreboard contains a record for `10tons` with 28,930 XP. A record has a 32-byte name followed by a little-endian integer. The integer is XP in Career and elapsed seconds in Survival. The writer and reader are at `0x401940` and `0x401a40`.

## 1.3.0 — co-op and authored levels

The title offers a second player. Survival's spawn interval becomes 0.25 seconds divided by the player count. The two entry positions oscillate on opposite sides. The pool grows to 512 creatures, with ordinary Survival rewards of 140–169 XP. Compare the paired arrivals at `0x416fa9` and the individual spawn at `0x40ba70` with the earlier addresses above.

At the title screen, hold **left Ctrl** and type **LEVELS**, then cycle the game mode to **Level Test**. The key sequence is in the dispatcher at `0x4145b3`. Four numbered maps cycle in order. The ZIP also carries three other map files and a separate `tiles.paq`. Level Test can place creatures that wait for the player to approach and triggers that grant a weapon. Its spawner gives placed creatures 300 health instead of scaling health with elapsed time.

The score writer at `0x404510` saves the name, time, XP, frame-rate statistics and game version. The encoder at `0x4043d0` protects the record table. A single checksum follows all records in the file.

## 1.3.1 and 1.4.0 — back to the arena

The 1.3.1 and 1.4.0 readmes describe levels as disabled. Neither ships the 1.3.0 maps. 1.3.1 is a comparison build in this project. Its shared art and combat code help distinguish features that already existed before the final freeware release. The 1.4.0 title exposes online services alongside the local game modes.

## What the clients reproduce

The early clients load each edition's own artwork, font and sounds, and implement its title choices, Survival arrivals and score format. The 1.3.0 client also loads the shipped numbered maps. The clients share later recovered code for parts of player movement, weapons, perks, HUD and effects. Those paths still need comparisons against each earlier executable before they can serve as evidence of historical behavior.
