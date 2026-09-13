# Creature interaction boundaries

Three small source changes recover distinct native details in `creature_update_all`:

- The interaction distance uses the corrected float length helper on a vector
  subtraction. Native `0x426f65..0x426fa6` stores the result with `fst` and
  compares the still-wide x87 value against 100. The previous scalar expression
  popped and reloaded the rounded float before that first comparison.
- That distance has a separate local from the earlier targeting distance.
  Native uses different homes for them (`esp+0x18` and `esp+0x14`).
- Contact direction reloads the creature's selected player after
  `player_take_damage`, matching native near `0x42733a`. Other later player-index
  reloads remain source work; no general callback equivalence is claimed.

The retained source reaches **57.316149%**, **1300/1338** instructions and
**228/0/1** clean/unresolved/mismatched positional references, from
54.952562%, 1297/1338 and 225/0/2. This adds 125.979183 fuzzy-weighted bytes.
The frame remains 108 versus native's 124 bytes, the exact prefix remains zero,
and both normalized and encoded-body exactness remain false. No full match
or new exact byte credit is added. Compiler flags, aliases and extent are unchanged.

The replay checks 192 radius-boundary cases and all 2,472 historical creature
fixtures under PC24 and PC64. All three recovered stages agree with native
state, ordered writes and modeled calls. The previous source differs in all
96 PC64 boundary cases, including state changes when Radioactive is enabled;
no PC24 case differs. The first small witness is position
`(0.10000000149011612, 99.99994659423828)` relative to player `(0, 0)`.
Its wide distance is below 100 but rounds to float 100. Later radius checks
still consume the stored distance, as native does. This PC64 result is diagnostic;
the game-precision PC24 behavior is preserved and neither modern port changes.

Twelve callback controls temporarily set the creature's target to player 1
at the modeled damage call and restore it at normalization. They distinguish
native's contact-direction reload from a freshly compiled no-reload control.
A disabled adapter must reproduce ordinary execution on both sides before
these witnesses run. This tests an ABI dependency, not actual helper mutation.
The existing finite callback models and their limitations are documented in
`../creature-state-publication-2026-09-11/README.md`.

`before.cpp` pins the predecessor at commit `97d9b9108fcc` (source SHA-256
`c5bce487a3bb6a0b890b33cd9af9ff273a1ef45db1e42c19ac330b1b2e3159b2`).
`recover.py` reconstructs every measured stage; `results.json` records source,
native body, compiler, harness, layout and observation hashes.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/creature-interaction-boundaries-2026-09-13/verify.py \
  --out /private/tmp/creature-interaction-proof
```
