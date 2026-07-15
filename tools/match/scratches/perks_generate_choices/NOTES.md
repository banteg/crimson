# `perks_generate_choices`

Native target: `crimsonland.exe` at `0x004045a0` (535 bytes, 139
instructions).

The recovered MSVC 6.5 `/O2 /GB` C source is exact:

```txt
match=100.00% prefix=139/139 target_insns=139 candidate_insns=139 refs=54/0/0
```

## Recovered source shape

- The function clears and fills all seven choice slots regardless of how many
  entries the current perk UI will display.
- On the Hidden Evil quest, unowned Monster Vision is forced into slot zero and
  random generation starts at slot one.
- Every retry calls `perk_select_random`. Pyromaniac is rejected unless player
  zero currently holds the Flamethrower.
- While Death Clock is active, eleven meaningful perk IDs are rejected. The
  native chain also compares against `perk_id_count`, a one-past-last sentinel
  initialized to 58 while the random selector can only return 1 through 57;
  that comparison is therefore unreachable rather than an omitted real perk.
- Jinxed, Ammunition Within, Anxious Loader, and Monster Vision each consume a
  second RNG draw and are rejected when its low two bits equal one.
- Before 10,001 attempts, duplicate and already-owned non-stackable perks are
  rejected. Stackable perks are always accepted; after 10,000 attempts they
  bypass even the duplicate scan, and after 29,999 attempts any eligible perk
  is accepted. Reaching 25,000 attempts logs the randomizer warning.
- Tutorial mode overwrites the completed array with Sharpshooter, Long Distance
  Runner, Evil Eyes, Radioactive, and three Fastshot entries.

An explicit `while (1)` retry/duplicate scan recovers the native unrotated loop
without qualifiers or dummy accesses. The surrounding perk helpers are also
exact as C translation units, and compiling this scratch as C recovers the
same 139-instruction body.

## Port parity

Python and Zig already preserve the fixed seven-slot RNG consumption, forced
Monster Vision slot, Death Clock exclusions, rarity draws, retry thresholds,
and tutorial list. Their omission of the unreachable `perk_id_count` comparison
is semantically neutral. The optional non-bug-compatible co-op Pyromaniac rule
is an explicit port improvement; bug-compatible mode retains the native
player-zero-only check.
