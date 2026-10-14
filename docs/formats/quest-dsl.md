---
tags:
  - formats
  - rewrite
---

# Quest construction language (Python prototype)

An experimental authoring language for #638. A recipe runs once and produces a
finite, ordered table of existing spawn-template invocations. It has no callbacks
during gameplay and cannot change creature behavior, collision or arena geometry.

The Python compiler and recipes for all 50 stock quests are implemented, and the
Python port, the browser/desktop `crimson-core` client, and the leaderboard service
play, verify, and rank custom quests: a recipe resolves into a `CustomQuest`
definition, which a run starts the way the original starts a quest and which its
replay carries ([replay format 33](replay.md#runspec)). Publishing a custom quest
(`crimson quest publish` / `POST /api/quests`) requires a verified completion replay
and creates its page and leaderboard at `/q/<id>`.
The compiler's JSON output is an inspection artifact, not an interchange format.
Existing stock builders remain the game's authoritative implementation.

## Try it

From a checkout with the Python dependencies installed:

```sh
uv run crimson --custom-quest src/crimson/quests/dsl/examples/crosswind.quest
uv run python -m crimson.quests.dsl --stock 4.7 --seed 0xBEEF
uv run python -m crimson.quests.dsl --stock 4.7 --players 4 --hardcore
uv run python -m crimson.quests.dsl --file src/crimson/quests/dsl/examples/clockwork.quest --output /tmp/clockwork.json
uv run python -m crimson.quests.dsl --file src/crimson/quests/dsl/examples/crosswind.quest
uv run pytest tests/quests/test_quest_dsl.py -q
```

`--seed` is a construction seed. It is not yet a gameplay start seed. JSON includes
the resolved positions, headings, counts, trigger times, starting weapon and terrain
slots. Each entry also has a source location that is unique within the plan: its
line, enclosing loop iterations, pattern call-site lines and position in a `place` list.

## A recipe

The syntax uses indentation. Each statement occupies one line; a bracketed list
may continue over several. Comments start with `#`; expressions use familiar
arithmetic, comparisons and indexing. The grammar in
[`quest.lark`](https://github.com/banteg/crimson/blob/master/src/crimson/quests/dsl/quest.lark)
is the syntax's specification: a [Lark](https://github.com/lark-parser/lark) LALR
grammar, so syntax errors name the line, the unexpected token and what could come next.

```text
quest "Clockwork" version 1
weapon assault_rifle
terrain (0, 1, 0)

let sockets = ring(center, radius=320, count=8)
let entrances = ["north", "east", "south", "west"]

pattern reinforcement(side):
    spawn formation.alien_ring at edge(side, outside=160)

repeat 8 as i:
    at 1s + i * 6s:
        spawn nest.alien_slow at sockets[i]
    at 3s + i * 6s:
        reinforcement(entrances[i % 4])

at 50s:
    spawn spider.boss at (768, 512)
```

This constructs 17 native entries. Pattern calls expand before play. A template
is an opaque game primitive: offspring, formation members and AI remain native.

## Statements and values

| Syntax | Meaning |
| --- | --- |
| `quest "Title" version 1` | Required header |
| `author "Name"` | Optional byline under the title: 1..31 printable ASCII characters; presentation only |
| `weapon pistol` | Starting weapon; lowercase `WeaponId` name, default `pistol` |
| `terrain (0, 1, 0)` | Three terrain-slot IDs in 0..7, default `(0, 1, 0)` |
| `order chronological` | Stable sort by trigger time, retaining construction order for ties; default |
| `order as-written` | Keep construction order; see [table order](#table-order) |
| `no_bonuses [...]` | Disable random bonus drops (bonus IDs 2..14; `points` stays enabled) |
| `no_perks [...]` | Disable perk offers (perk IDs 1..57; `instant_winner` stays enabled) |
| `no_weapons [...]` | Disable specific weapons (IDs 2..33) from random weapon drops |
| `fixed_weapon true` | Lock the run to the starting weapon (disables `weapon` bonus, weapon perks, and non-Pistol weapon drops) |
| `let name = expression` | Immutable local binding |
| `var cue = 2s` | Mutable construction-local binding |
| `cue += 500ms` | Update a declared mutable binding |
| `repeat N as i:` | Repeat with indices 0 through N−1 |
| `for pos in points:` | Iterate a bounded list or range; tuple destructuring is supported |
| `if condition:` / `elif` / `else:` | Construction-time decisions |
| `while condition:` / `break` | Construction-only loops, bounded by the compiler work budget |
| `at time:` | Absolute nominal quest time; applies to enclosed spawn/pattern operations |
| `spawn template at point_or_points [copies N]` | Emit one entry per point (single point or list of points), default count 1 |
| `burst template at point copies N` | Alias for `spawn` on a single point with count N |
| `place template on points [copies N]` | Alias for `spawn` on a list of points |
| `heading angle` | Optional suffix on spawn/burst/place; default 0 radians |
| `pattern name(args):` | Reusable construction block; declared before use; no recursion or return values |

Settings precede construction statements. Block-local declarations can shadow
outer values. Assignments update the nearest declared `var`; loop bindings are
local to each iteration. Patterns see their parameters and quest-scope bindings,
and inherit the caller's `at` time. They may also contain explicit `at` blocks.

Values are numbers, booleans (`true`/`false`), double-quoted strings, immutable lists,
points and template references. Words such as `at`, `heading` and `copies` act as
keywords only where the grammar expects one, so they remain usable as names. There are no mutable collections. `range(start, stop, step)`
has an exclusive stop. `+`, `-`, `*`, `/`, `//`, `%`, unary signs, `and`, `or`,
`not`, comparisons, membership, indexing and conditional expressions are supported.
Points add and subtract, and scale by numbers (`west + point(0, 158)`,
`start + direction * 62.4`); lists have no arithmetic or comparisons.
Comparisons use scalar values or points; membership uses lists of those values.

Time literals `500ms`, `2s`, `2.5s` resolve to whole integer milliseconds. Bare
integers used as times also mean milliseconds. Angle literals such as `90deg`
resolve to radians; bare angles are radians. Units are literal conveniences,
not a dimension/type system. `at` never means time relative to a previous block.

Available construction inputs are `players` (1..4), `hardcore`, `center`
(`point(512, 512)`), `arena_size` (1024), `pi` and `tau`. In hardcore, the game
also adds 8 copies to every entry with more than one (2 for fast aliens, none for
plasma shooters); the compiler applies that rule after construction, as the game
does for every quest, so recipes read `hardcore` only to change their own design.

## Table order

The classic scheduler keeps no separate notion of a wave. Each frame it takes the
first due entry in table order, together with the entries immediately after it
that share its trigger time, and spawns that group. Once the arena has been empty
for 3 s, it takes the first remaining entry in table order early, whatever its
time. So the table is a queue:

- Entries with the same time arrive together only when they are adjacent. Two
  same-time entries separated by another time arrive on consecutive frames.
- Clearing the arena early brings forward whatever is next in the queue. In a
  chronological table that is the next wave by time; otherwise it may be a later one.

The scheduler spawns one group per frame. Groups that fall due together queue up a
frame apart, so same-time entries split by other times, or many groups due at once,
arrive late by a frame each, and in a dense table those frames add up. Beyond that,
order matters only to fast players. Several stock quests list entries out of time
order, and early clears expose it:

- The Beating lists all its ghosts before its alien rings, although both arrive
  from 40 s. An early clear brings only the ghosts forward; the rings keep their time.
- Lizard Raze lists its three lizard dens after every lizard wave. An early clear
  brings the next wave forward; the dens still wait for 10 s.
- Spider Spawns lists its inner nests at 20.5 s, 26 s, 31.5 s and 22 s, mixed
  with spiders at 21 s. Early clears pull them forward in that listed order.

`order chronological`, the default, gives the intuitive queue. Stock recipes for
quests whose table is not chronological use `order as-written` and say what
queues out of time order.

## Template vocabulary and geometry

All implemented `SpawnId` members have a canonical reference such as
`template.alien_small_gray_26`. The unused `0x02` template is excluded. Numeric
native IDs are also accepted. Short aliases currently cover:

- `alien.small_gray`, `alien.fast`
- `zombie.random`, `zombie.spawner_boss`
- `spider.small_blue`, `spider.plasma`, `spider.splitter`, `spider.boss`
- `nest.alien`, `nest.alien_slow`, `nest.spider`, `nest.plasma`
- `formation.alien_ring`, `formation.lizard_chain`, `formation.alien_grid`,
  `formation.spider_grid`, `formation.lizard_grid`

These are selections from the existing catalog, not new enemy definitions.
`place alien.small_gray on ring(...)` creates independent enemies; spawning
`formation.alien_ring` invokes the original linked formation.

| Helper | Result |
| --- | --- |
| `point(x, y)` or `(x, y)` at a spawn | A position; `.x`/`.y` are available on `point` values |
| `edge("west", outside=64, fraction=0.5)` | Point along an arena edge; also east/north/south |
| `edge_line(side, count, spacing, outside=64)` | Ordered centered line outside an edge; ascending x for north/south, ascending y for west/east |
| `opposite(side)` | The opposing cardinal edge name |
| `corner("northwest", outside=64)` | A point beyond an arena corner; also northeast/southwest/southeast |
| `corners(outside=64)` | Ordered northwest, northeast, southwest, southeast corner points |
| `line(start, step, count)` | Ordered positions, advancing by a vector |
| `ring(center, radius, count, start=0)` | Ordered evenly spaced positions, clockwise in screen coordinates |
| `polar(center, radius, angle)` | One circular position |
| `arc(center, radius, start, sweep, count)` | Ordered positions including both endpoints; positive sweep is clockwise; a singleton is at start |
| `rotate(points, angle, around=center)` | Rotate positions clockwise for positive angles; preserve list order and the input list |
| `facing(point, target)` | The heading that faces `target` from `point` |
| `min`, `max`, `abs`, `int`, `float`, `len` | Construction calculations; min/max take numbers or one numeric list |

Geometry uses ordinary double-precision math; emitted positions and headings are
stored as float32, like native entries. Off-arena positions are allowed because
the stock quests deliberately use them. Rotating a position does not rotate a
native formation's internal offsets.

`rand()` draws from the construction MSVCRT stream (0..32767). `choose(list)` and
`rand_int(low, high)` (inclusive) use a draw modulo the list length/range width;
they are reproducible, but not unbiased sampling over arbitrary ranges.

`shuffle(list)` returns a new immutable list using Fisher–Yates, consuming one
construction draw for each index from N−1 down to 1. Each swap index is the draw
modulo (index+1). Input order is preserved in the original list, and empty or
singleton lists consume no draws. Shuffling uses the same construction stream
as `choose` and `rand_int`.

## Stock quests

Every campaign quest has a recipe in `src/crimson/quests/dsl/stock/`, written as
a designer would describe it rather than transcribed from the builder. The recipes
are a corpus the language must express: loops, player and hardcore scaling, edge,
corner, ring and spiral geometry, random placement, and out-of-order queues.

The test compares each recipe with its stock builder for players 1..4, both
hardcore settings and four seeds. The recipe's `rand()` uses the same seeded stream
as the builder:

- The ordered sequence of template, count and trigger time must match exactly,
  since that is everything the scheduler reads.
- Positions must agree within 0.01 px and headings within 1e-4 rad. Recipes use
  plain arithmetic; there is no float32 or x87 emulation.
- Random choices draw from the stream in the builder's order, so Target Practice,
  Sweep Stakes, Deja vu and The Random Factor match exactly.

The Killing is the one listed exception. The original rolls a random enemy and side
for each wave, then ignores both, so its rotation is fixed. The recipe skips those
ignored rolls, so its random nests land elsewhere for the same seed; the test checks
they stay within the original's 128..895 square, and still checks every heading.

## Example encounter library

`src/crimson/quests/dsl/examples/` contains the scenarios from the design discussion.
These are structurally validated authoring fixtures for future playtesting and
challenge curation. They have no verified clears or balance claims yet.
Entry counts measure native template invocations in the timeline, not total
creatures or offspring. All recipes fit the existing 256-entry table.

| Recipe | Entries | Design decision |
| --- | ---: | --- |
| `clockwork.quest` | 17 | Eliminate successive nests while native formations arrive |
| `crosswind.quest` | 120 | Alternating ranged pressure against growing melee crowds |
| `spiral-descent.quest` | 60 | Manage contracting arrival positions; movement remains native |
| `accelerating-encounters.quest` | 12 | Increasing native bursts with shrinking wave intervals |
| `shuffled-threats.quest` | 8 | Reproduce a construction-seeded deal of threats and entrances |
| `plasma-orchard.quest` | 55 | Choose which ranged nest to eliminate while melee crosses the arena |
| `moving-factory.quest` | 17 | Pursue a mobile spawner or create space in its crowds |
| `split-decision.quest` | 65 | Choose safe finishing positions for opposing splitters |
| `formation-parade.quest` | 12 | Break native rings, chains and grids before the next arrival |
| `closing-circle.quest` | 240 | Preserve an escape route through a rotating 60-degree gap |
| `nest-circuit.quest` | 24 | Follow a tightening nest activation schedule or cut across it |
| `same-problem-assault-rifle.quest` | 61 | Compare the same encounter with different starting weapons |
| `same-problem-shotgun.quest` | 61 | Same ordered entries and terrain as the Assault Rifle variant |
| `same-problem-gauss-gun.quest` | 61 | Same ordered entries and terrain as the Assault Rifle variant |

The three weapon variants deliberately keep their encounter bodies identical.
They change only the title and starting weapon; a regression check preserves
entry-for-entry equality. Crosswind retains the design discussion's exact eight
waves, while the named scenario sketches now have concrete timings and counts.

```python
from crimson.quests.dsl import build_custom_quest, compile_quest

plan = compile_quest(source, seed=0xBEEF, player_count=1, hardcore=False)
entries = plan.entries
quest = build_custom_quest(source, seed=0xBEEF)
```

`compile_quest` constructs the table one variant plays. `build_custom_quest`
resolves a recipe into the single-table definition a custom quest run plays
(`RunSpec.custom_quest`): the title, author, starting weapon, terrain slots,
resolved `entries`, and drop/offer restrictions (`no_bonuses`, `no_perks`, `no_weapons`).
`crimson --custom-quest` builds one with construction seed 0 and starts it in ranked mode
straight after boot; `crimson quest publish` uploads the recipe alongside a completed
replay to establish its leaderboard on `crimson.land/q/<id>`.

## Bounds and runtime semantics

Default limits: 64 KiB source, 10,000 AST nodes, syntax/pattern depth 64, 100,000
construction work units, 4,096 items per collection, 256 emitted entries and a
one-hour nominal time horizon. Copies are capped at 384 per entry and per trigger
time (the size of the creature pool) and 8,192 per quest, counted after the
hardcore adjustment; the stock quests peak at 108 per trigger time and 2,000 in
total. Integer intermediates have at most 64 magnitude bits, and numbers and point
coordinates must be finite. Spawn positions must lie within −1024..2048 on both axes:
a full arena beyond each edge, which every stock arrival fits. Work accounts for interpreted statements, expressions,
iteration and collection operations; it also stops loops that emit nothing.

The compiler interprets the parse tree directly; anything outside the grammar is a
syntax error, and nothing is evaluated as Python. Calls reach only the listed helpers,
and each helper's arguments are checked against its declared parameter types (points,
finite numbers, integers, strings, lists) before it runs. Names beginning with `_`,
recursion and access to live game state are unavailable.

Copies count template invocations, not creatures: formations bring their members
and nests keep spawning. These limits are not a guarantee about creature or spawner
occupancy during every possible run; pool saturation reporting belongs in later
playtesting work.

The plan assumes the existing **classic quest scheduler** and clear-all objective.
Times are nominal gameplay-clock triggers with a strict due-time comparison;
[table order](#table-order) decides grouping and early dispatch. There is no exact
wall-clock scheduling, kill-triggered scripting or enforced deadline. The stock
`time_limit_ms` metadata is deliberately not exposed as an objective.
