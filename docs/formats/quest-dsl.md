# Quest construction language (Python prototype)

An experimental authoring language for #638. A recipe runs once and produces a
finite, ordered table of existing spawn-template invocations. It has no callbacks
during gameplay and cannot change creature behavior, collision or arena geometry.

The Python compiler and 50 independent stock-quest translations are implemented.
Custom run initialization, browser loading, replay embedding and publication are
not implemented by this prototype. Its JSON output is an inspection artifact,
not a frozen interchange or replay format. Existing stock builders remain the
game's authoritative implementation and the parity oracle.

## Try it

From a checkout with the Python dependencies installed:

```sh
uv run python -m crimson.quests.dsl --stock 4.7 --seed 0xBEEF
uv run python -m crimson.quests.dsl --stock 4.7 --players 4 --hardcore
uv run python -m crimson.quests.dsl --file src/crimson/quests/dsl/examples/clockwork.quest --output /tmp/clockwork.json
uv run python -m crimson.quests.dsl --file src/crimson/quests/dsl/examples/crosswind.quest
uv run pytest tests/quests/test_quest_dsl.py -q
```

`--seed` is a construction seed. It is not yet a gameplay start seed. JSON includes
the resolved positions, headings, counts, trigger times, source lines/iteration
indices, starting weapon, terrain slots and final construction RNG state.

## A recipe

The syntax uses indentation. Each statement occupies one physical line. Comments
start with `#`; expressions use familiar arithmetic, comparisons and indexing.

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
| `weapon pistol` | Starting weapon; lowercase `WeaponId` name, default `pistol` |
| `terrain (0, 1, 0)` | Three terrain-slot IDs in 0..7, default `(0, 1, 0)` |
| `order chronological` | Stable sort by trigger time, retaining expansion order for ties; default |
| `order native` | Preserve expansion order, including unsorted stock tables |
| `counts explicit` | Use exactly the constructed counts; default |
| `counts native` | Apply the stock hardcore count adjustment once, after construction |
| `let name = expression` | Immutable local binding |
| `var cue = 2s` | Mutable construction-local binding |
| `cue += 500ms` | Update a declared mutable binding |
| `repeat N as i:` | Repeat with indices 0 through N−1 |
| `for pos in points:` | Iterate a bounded list or range; tuple destructuring is supported |
| `if condition:` / `elif` / `else:` | Construction-time decisions |
| `while condition:` / `break` | Construction-only loops, bounded by the compiler work budget |
| `at time:` | Absolute nominal quest time; applies to enclosed spawn/pattern operations |
| `spawn template at point` | One native template invocation, count 1 |
| `burst template at point copies N` | One native entry with count N and native alternating offsets |
| `place template on points` | One entry per point, each with count 1 |
| `heading angle` | Optional suffix on spawn/burst/place; default 0 radians |
| `pattern name(args):` | Reusable construction block; declared before use; no recursion or return values |

Settings precede construction statements. Block-local declarations can shadow
outer values. Assignments update the nearest declared `var`; loop bindings are
local to each iteration. Patterns see their parameters and quest-scope bindings,
and inherit the caller's `at` time. They may also contain explicit `at` blocks.

Values are numbers, booleans (`true`/`false`), strings, immutable lists, points and
template references. There are no mutable collections. `range(start, stop, step)`
has an exclusive stop. `+`, `-`, `*`, `/`, `//`, `%`, unary signs, `and`, `or`,
`not`, comparisons, membership, indexing and conditional expressions are supported.
Collection comparisons and collection arithmetic are excluded. Comparisons use
scalar values or points; membership uses lists of those values.

Time literals `500ms`, `2s`, `2.5s` resolve to whole integer milliseconds. Bare
integers used as times also mean milliseconds. Angle literals such as `90deg`
resolve to radians; bare angles are radians. Units are literal conveniences,
not a dimension/type system. `at` never means time relative to a previous block.

Available construction inputs are `players` (1..4), `hardcore`, `center`
(`point(512, 512)`), `arena_size` (1024), `pi`, `tau` and `native_tau`.

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
| `edge_points(offset=64)` | `.left`, `.right`, `.top`, `.bottom` midpoints |
| `edge_line(side, count, spacing, outside=64)` | Ordered centered line outside an edge; ascending x for north/south, ascending y for west/east |
| `opposite(side)` | The opposing cardinal edge name |
| `corners(offset=64)` | Ordered top-left, top-right, bottom-left, bottom-right points |
| `line(start, step, count)` | Ordered positions, advancing by a vector |
| `ring(center, radius, count, start=0)` | Ordered evenly spaced positions, clockwise in screen coordinates |
| `polar(center, radius, angle)` | One circular position |
| `arc(center, radius, start, sweep, count)` | Ordered positions including both endpoints; positive sweep is clockwise; a singleton is at start |
| `rotate(points, angle, around=center)` | Rotate positions clockwise for positive angles; preserve list order and the input list |
| `ring_angles(center, radius, count, step=..., start=0)` | Ordered `(point, angle)` pairs with an explicit native angle step |
| `radial(center, angle, start, stop, step)` | Ordered positions along integer radii; native radial rounding |
| `heading_from_center(point, center)` | Native outward heading calculation |
| `min`, `max`, `abs`, `int`, `float`, `len` | Construction calculations; min/max take numbers or one numeric list |

Geometry helper point arguments use `point(...)` values or `center`. Off-arena
positions are allowed because the stock quests deliberately use them. Rotating
a position does not rotate a native formation's internal offsets.

## Stock coverage and numerical compatibility

Every campaign quest has a recipe in `src/crimson/quests/dsl/stock/`. These keep
loops, counters, conditionals and geometry; they do not call the stock builders
or substitute precomputed tables. Gauntlet and the spiral in The Spanking Of The
Dead are compact examples of the authoring vocabulary.

The test matrix compares all 50 recipes against `build_quest_spawn_table` with
four seeds, players 1..4 and both hardcore settings: **1,600 cases**. It checks
ordered entries, float32 position/heading bits, starting weapon, terrain and
the complete RNG trace (values, states and caller addresses).

Ordinary expression arithmetic uses Python numbers, with emitted positions and
headings rounded to finite float32 values. Exact stock math sometimes needs
explicit `f32`, `pc24_add`, `pc24_sub`, `pc24_mul`, `pc24_div`, `angle_step` and
`random_angle`. Geometry helpers reuse the existing native rounding routines.
These compatibility operations are useful evidence about the language's coverage;
new recipes can usually use ordinary arithmetic.

`rand()` draws from the construction MSVCRT stream. `choose(list)` and
`rand_int(low, high)` (inclusive) use a draw modulo the list length/range width;
they are reproducible, but not unbiased sampling over arbitrary ranges.
`rand(caller_address)` preserves a native caller tag. Standalone `rand(...)`
statements express discarded draws, including The Killing's original bug.

`shuffle(list)` returns a new immutable list using Fisher–Yates, consuming one
construction draw for each index from N−1 down to 1. Each swap index is the draw
modulo (index+1). Input order is preserved in the original list, and empty or
singleton lists consume no draws. Shuffling uses the same construction stream
as `choose` and `rand_int`.

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

The normal API owns its RNG:

```python
from crimson.quests.dsl import compile_quest

plan = compile_quest(source, seed=0xBEEF, player_count=1, hardcore=False)
entries = plan.entries
```

For parity research, `compile_quest(source, context=QuestContext(...))` consumes
the supplied RNG at its current state, just as a stock builder does. That context
is authoritative over the convenience seed/player/hardcore arguments, and is
mutated even if compilation subsequently fails. This is not the custom-run
initialization contract; a future loader must define gameplay startup explicitly.

## Bounds and runtime semantics

Default limits: 64 KiB source, 10,000 AST nodes, syntax/pattern depth 64, 100,000
construction work units, 4,096 items per collection, 256 emitted entries, 4,096
copies per entry and a one-hour nominal time horizon. Integer intermediates have
at most 64 magnitude bits. Work accounts for interpreted statements, expressions,
iteration and collection operations; it also stops loops that emit nothing.

The compiler interprets an allowlisted AST after lowering the surface syntax. It
does not use Python `eval` or `exec`. Imports, arbitrary calls, private attributes,
comprehensions, recursion and access to live game state are unavailable.

These are construction limits, not a guarantee about creature/spawner occupancy
during every possible run. Native templates can allocate many entities or create
offspring; pool saturation reporting belongs in later playtesting work.

The plan assumes the existing **classic quest scheduler** and clear-all objective.
Times are nominal gameplay-clock triggers, with the existing strict due-time
comparison and early dispatch after the arena remains empty. There is no exact
wall-clock scheduling, kill-triggered scripting or enforced deadline. The stock
`time_limit_ms` metadata is deliberately not exposed as an objective.
