---
tags:
  - formats
  - rewrite
  - replay
---

# Replay format (v20)

A replay (`.crd`) records one run: the settings it started from, every tick's
inputs, and the result the recording game derived when the run ended. A
verifier re-simulates the ticks and must derive the identical result.

Replays are recorded by the port's live game. Original-game captures use a
separate debug container (see [capture replays](#original-captures)).

## Envelope

A file is exactly one zstd frame (no trailing bytes) whose content is a
msgpack payload. Limits: 65 MiB file, 64 MiB payload, 8 MiB zstd window.
Writers enforce the same limits, so a very long run can outgrow the format;
the game then logs that the replay was not saved.

The payload must be **canonical**: it must equal the byte-for-byte encoding of
the value it decodes to. Concretely:

- maps are encoded with their keys in the declared order below, every key
  present, no duplicates, no extra keys;
- integers use the shortest msgpack encoding (positive values as fixint/uint*,
  negative values as fixint/int*);
- every float field is a msgpack `float64` (never `float32`, never an integer)
  holding a finite value exactly representable as `float32`;
- strings, arrays and maps use their shortest length headers;
- `null` is msgpack nil, booleans are msgpack booleans.

One canonical byte string per replay means the SHA-256 of the payload
identifies the run, and no two parsers can disagree about which duplicate or
alternative encoding "wins".

## Payload

`Replay` is a map:

| Key | Type | Meaning |
|---|---|---|
| `format_version` | int | `20` |
| `game_version` | str | Build that recorded the run (see below) |
| `run` | `RunSpec` | Run start settings |
| `result` | `RunResult` | Result the recorder derived |
| `ticks` | array of `Tick` | At least one tick |

`game_version` is the package version for a release-tagged build
(`0.10.0`), else `<version>+g<12-hex commit>`. A checkout whose `src/` differs
from that commit (modified or new unignored files) appends `.dirty`.

### RunSpec

| Key | Type | Meaning |
|---|---|---|
| `game_mode_id` | int | 1 Survival, 2 Rush, 3 Quests, 4 Typ-o, 8 Tutorial |
| `seed` | u32 | CRT RNG state before the run's first terrain draw |
| `quest_level` | `{major, minor}` map or nil | Required for quests only; 1..5 / 1..10 |
| `player_count` | int | 1..4; Typ-o and Tutorial require 1 |
| `hardcore` | bool | |
| `preserve_bugs` | bool | Native quirks mode |
| `demo` | bool | Shareware demo build |
| `quest_fail_retry_count` | int 0..2³¹−1 | Native retry scaling counter |
| `detail_preset` | int 1..5 | Presentation detail; native presentation code consumes RNG |
| `violence_disabled` | int 0..255 | Native config byte; likewise |
| `status` | `RunStatus` | Save-status fields that influence the run |
| `typo_dictionary_words` | array of str | Optional custom Typ-o dictionary: at most 2048 words of 1..15 printable ASCII characters |
| `typo_highscore_names` | array of str | Typ-o name pool from the local score table: at most 512 names of 1..31 ASCII letters or `.` |

`RunStatus` is a map of `quest_unlock_index` (i32), `quest_unlock_index_full`
(i32) and `weapon_usage_counts` (exactly 53 u32 values). Unlock indices gate
weapons, perks and terrain; usage counts steer native weapon-drop rerolls.

### Tick

A tick is a two-element **array** `[inputs, commands]`:

- `inputs`: exactly `player_count` arrays `[move_x, move_y, aim_x, aim_y, flags]`,
  four f32 axes and an integer flag word (bit layout in
  `crimson/replay/types.py`; unknown bits and inconsistent presence bits are
  invalid).
- `commands`: ordered array of command maps, each with a `type` key first:

| `type` | Other keys | Rule |
|---|---|---|
| `perk_menu_open` | `player_index` | a perk must be pending and a player alive |
| `perk_pick` | `player_index`, `choice_index` 0..6 | as above, and the index must name an offered choice |
| `typo_char` | `player_index`, `ch` (one character) | Typ-o only |
| `typo_backspace` | `player_index` | Typ-o only |
| `typo_submit` | `player_index` | Typ-o only |

`player_index` must be below `player_count`. Command rules are checked
against the state left by the commands before them.

Every tick advances the simulation by `float32(1/60)` seconds in the native
1024×1024 arena. Perk commands apply at the start of the tick, before frame
timing is derived; Typ-o commands apply after the mode's pre-step hook, as in
live play. Typ-o fires and reloads only through typed words: the input fire
and reload flags have no effect there.

### RunResult

| Key | Type | Meaning |
|---|---|---|
| `outcome` | str | `death`, `quest_completed`, `tutorial_completed` or `incomplete` |
| `elapsed_ms` | int | Quest spawn timeline for quests, session time otherwise (truncated) |
| `kills` | int | Creature kill count (all players) |
| `rng_state` | u32 | CRT RNG state after the final tick |
| `pending_perks` | int | Unpicked perks |
| `quest_final_ms` | int or nil | Set only for `quest_completed`: base time minus life and unpicked-perk bonuses; may be negative, exactly zero becomes 1 |
| `players` | array of `PlayerResult` | Exactly `player_count` entries |

`PlayerResult` is a map of `experience` (int), `health` (f32),
`shots_fired` (int), `shots_hit` (int) and `most_used_weapon_id` (int). As in
the high-score record, hits are clamped to shots fired (a piercing shot can hit
several creatures). Typ-o reports submitted words as shots fired and matched
words as hits.

## Run end

The run ends on the first tick after which the mode's end condition holds:

| Mode | End condition after a tick |
|---|---|
| Survival | every player has health ≤ 0 and a negative death timer |
| Rush | every player has health ≤ 0 |
| Quests | quest completion transition finished (`quest_completed`), else as Survival (`death`) |
| Typ-o | the player has health ≤ 0 |
| Tutorial | none; the player leaves from the UI |

A replay whose run ends before its last tick is invalid. When the last tick
does not end the run, the outcome is `incomplete`, except:

- a quest where every player has health ≤ 0 is `death` (the failed-quest
  countdown keeps running while paused, so the run can close between ticks);
- a tutorial at stage 8 or later is `tutorial_completed`.

## Verification

A verifier decodes the payload (rejecting non-canonical encodings), checks the
constraints above, simulates every tick from the `RunSpec`, rejects illegal
commands and early run ends, derives the `RunResult` and compares it with the
recorded one field by field. It reports the payload SHA-256, the derived
result and any mismatched fields. A verifier may simulate a prefix for
debugging, but a prefix never verifies a result.

Verification establishes that the recorded inputs, replayed by the
verifier's simulation, produce the recorded result. The verifier reports the
replay's `game_version`; a service that ranks runs must verify each one with
the build that version names. Verification does not establish who produced the
inputs or in what real time.

The live game records only runs that stay within these rules: it stops
recording when a debug cheat changes the run outside recorded ticks, and the
perk prompt stays closed while a pick is waiting for the next tick.

## Original captures

Frida captures of the original executable need per-tick native frame deltas,
top-level RNG draws made between gameplay ticks, native menu activity observed
inside a tick, and creature-slot residue left by earlier runs. None of these
exist in port play, so they live in a debug-only capture container under
`crimson.dbg`, replayed by a Python debug driver. Replays never carry them.
