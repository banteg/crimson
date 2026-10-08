---
tags:
  - formats
  - rewrite
  - replay
---

# Replay format

A replay (`.crd`) records one run: the settings it started from, every tick's
inputs, and the result the recording game derived when the run ended. A
verifier re-simulates the ticks and must derive the identical result.

Replays are recorded by the port's live game.

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
| `format_version` | int | `31` |
| `game_version` | str | The build that recorded the run, which boards are versioned by (see below) |
| `rules` | int | The simulation rules the run plays under (since v31) |
| `recorder` | `Recorder` | The program that recorded the run (since v30) |
| `run` | `RunSpec` | Run start settings |
| `result` | `RunResult` | Result the recorder derived |
| `ticks` | array of `Tick` | At least one tick |

`game_version` is the package version for a release-tagged build or an
installed package (`0.11.0`), else `<version>+g<12-hex commit>`. A checkout
whose `src/` differs from that commit (modified or new unignored files) appends
`.dirty`.

`rules` is a number each build carries (`REPLAY_RULES`), raised whenever a change makes earlier replays play
differently: a replay plays back only under the rules it was recorded under. Readers accept v30, which had no
`rules`, as rules 1; writers always write v31.

`Recorder` is a map of `client` (`crimson` for this port; another client, such as a native crimson-core build,
names itself), `version` (that client's own build, in `game_version`'s form) and `platform` (`<os>-<cpu>`, such
as `macos-arm64`; `unknown` for the fixtures recorded before v30). Each is 1..64 printable ASCII characters.
Verification ignores it: `game_version` names the build, `recorder` who recorded the run, so boards can show,
filter or withdraw runs by client.

### RunSpec

| Key | Type | Meaning |
|---|---|---|
| `game_mode_id` | int | 1 Survival, 2 Rush, 3 Quests, 4 Typ-o, 8 Tutorial |
| `seed` | u32 | CRT RNG state entering `gameplay_reset_state()` at run start |
| `quest_level` | `{major, minor}` map or nil | Required for quests only; 1..5 / 1..10 |
| `player_count` | int | 1..4; Typ-o and Tutorial require 1 |
| `hardcore` | bool | |
| `preserve_bugs` | bool | Native quirks mode |
| `quest_fail_retry_count` | int 0..2³¹−1 | Native retry scaling counter |
| `detail_preset` | int 1..5 | Presentation detail; native presentation code consumes RNG |
| `violence_disabled` | int 0..255 | Native config byte; likewise |
| `friendly_fire` | bool | `cv_friendlyFire` at run start: player shots carry `-1 - player_index` and can hit other players (since v27) |
| `status` | `RunStatus` | Save-status fields that influence the run |
| `typo_dictionary_words` | array of str | Optional custom Typ-o dictionary: at most 2048 words of 1..15 printable ASCII characters |
| `typo_highscore_names` | array of str | Typ-o name pool from the local score table: at most 512 names of 1..31 ASCII letters or `.` |
| `typo_carry` | `TypoCarry` | Typ-o state the game keeps between runs (since v28); defaults outside Typ-o |

`TypoCarry` is a map of `target_world` (`{x, y}` f32 map or nil: the aim point
the last Typ-o run left, nil before the game's first Typ-o run),
`submit_count` and `match_count` (i32 word counters the game never resets;
a run scores only its own words unless `preserve_bugs`), and
`highscore_names_loaded` (bool: an earlier run already loaded the score-table
name cache, so this run's first highscore-name pick skips the table load's RNG
draws).

`RunStatus` is a map of `quest_unlock_index` (i32), `quest_unlock_index_hardcore`
(i32) and `weapon_usage_counts` (exactly 53 u32 values). Unlock indices gate
weapons, perks and terrain; usage counts steer native weapon-drop rerolls.

### Tick

A tick is a two-element **array** `[inputs, commands]`:

- `inputs`: exactly `player_count` arrays `[move_x, move_y, aim_x, aim_y, flags]`,
  four f32 axes and an integer flag word (bit layout in
  `crimson/replay/types.py`; unknown bits and inconsistent presence bits are
  invalid). Keyboard and joystick aim turn with their own held bits (the aim
  keys or the POV hat, since v25); the movement turn bits only steer movement.
  The aim axes are the world aim point, except under relative mouse aim (the
  screen cursor) and dual action pad aim (the stick's reach, which the
  simulation adds to the position the tick's movement produced; since v29).
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
1024×1024 arena. Perk picks apply at the start of the tick, before frame
timing is derived; a perk menu open generates its choices after the tick's
level-up check and before `bonus_update`, where native opens the menu; Typ-o
commands apply after the mode's pre-step hook, as in live play. Typ-o fires and reloads only through typed words: the input fire
and reload flags have no effect there. Each tick ends with native `game_frame_update`'s
discarded RNG draw, and so does run setup; frames outside gameplay add none.

### RunResult

| Key | Type | Meaning |
|---|---|---|
| `outcome` | str | `death`, `quest_completed`, `tutorial_completed` or `incomplete` |
| `elapsed_ms` | int | Quest spawn timeline for quests, session time otherwise (truncated) |
| `kills` | int | Creature kill count (all players) |
| `shots_fired` | int | Shots fired by all players, native `highscore_record_shots_fired` (since v26) |
| `shots_hit` | int | Creature hits by any shot, native `highscore_record_shots_hit` |
| `rng_state` | u32 | CRT RNG state after the final tick |
| `pending_perks` | int | Unpicked perks |
| `quest_final_ms` | int or nil | Set only for `quest_completed`: base time minus life and unpicked-perk bonuses; may be negative, exactly zero becomes 1 |
| `players` | array of `PlayerResult` | Exactly `player_count` entries |

`PlayerResult` is a map of `experience` (int), `health` (f32) and
`most_used_weapon_id` (int). As in the high-score record, hits are clamped to
shots fired (a piercing shot can hit several creatures). Typ-o reports
submitted words as shots fired and matched words as hits.

## Run end

The run ends on the first tick after which the mode's end condition holds:

| Mode | End condition after a tick |
|---|---|
| Survival | every player has health ≤ 0 and a negative death timer |
| Rush | every player has health ≤ 0 |
| Quests | as Survival (`death`), else the quest completion transition finished (`quest_completed`) |
| Typ-o | the player has health ≤ 0 |
| Tutorial | none; the player leaves from the UI |

After the tick that ends the run the game keeps simulating while the gameplay
timeline runs down, as native does: from at most 500 ms, by the whole
milliseconds of each tick's simulated time (`int(dt_sim * 1000)`), before it
leaves for the game-over or quest screen. A replay may continue through that
run-down but no further: counting 500 down from the end tick by each tick's
milliseconds, a replay with ticks left once the count drops below 0 is invalid.
The outcome is the one standing after the last tick. When no tick ends the run,
the outcome is `incomplete`, except:

- a quest where every player has health ≤ 0 is `death` (the failed-quest
  countdown keeps running while paused, so the run can close between ticks);
- a tutorial at stage 8 or later is `tutorial_completed`.

## Verification

A verifier decodes the payload (rejecting non-canonical encodings), checks the
constraints above, simulates every tick from the `RunSpec`, rejects illegal
commands and ticks past the run-down, derives the `RunResult` and compares it with the
recorded one field by field. It reports the payload SHA-256, the derived
result and any mismatched fields. A verifier may simulate a prefix for
debugging, but a prefix never verifies a result.

Verification establishes that the recorded inputs, replayed by the
verifier's simulation, produce the recorded result. The verifier reports the
replay's `game_version`; a service that ranks runs must verify each one with
the build that version names. Any build plays back and verifies a replay of
its own format version, warning when the recording build differs: a rules
change between the two shows up as a result mismatch. Verification does not establish who produced the
inputs or in what real time.

The live game simulates exactly the inputs it records: it rounds each tick's
inputs to the stored form (f32 axes, packed flags) before stepping, so no
precision the file cannot hold reaches the simulation.

The live game records only runs that stay within these rules: it stops
recording when a debug cheat changes the run outside recorded ticks, and the
perk prompt stays closed while a pick is waiting for the next tick.
