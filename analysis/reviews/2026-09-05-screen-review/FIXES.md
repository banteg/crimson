# Screen review implementation

Implemented the approved report in conventional commits, without rewriting
the report's historical probes or recorded evidence.

## Commits

| Commit | Change |
| --- | --- |
| `0f7ab8e37` | Controls capture owns input before Back; one capture record fixes player-zero rendering (C1/C2). |
| `0a011e0fd` | Score refresh preserves query/dirty state; Back restores native return context; Play launches the selected unlocked mode/quest (C3/C4/C5). |
| `05db5f25b` | Typed requests carry launch, score, and result payloads; one screen stack owns open screens, resumption, and gameplay backgrounds. Shared resources outlive Boot. |
| `2dae395a8` | Compose menu/panel transitions and shared animation, layout, sign, background, and cursor functions. Remove cross-screen private MenuView calls and duplicated Play Game/Options loops. Controls and High Scores each use one dropdown selection with explicit input precedence. |
| `fcda6741d` | Explicit quit/screenshot callbacks replace reflective runner hooks; debug factories use one typed signature. |
| `f96fae246` | Lazy demo construction passes demo settings into the world constructor; asset lifecycle tests target the runtime owner. |

## Ownership and behavior

`ScreenNavigator` applies typed requests to `GameState.screens`. Stack entries
declare their resume callback and, for runs, their gameplay background. Pushing
retains the parent; Back disposes the child and resumes the parent. Replacement
and returning to the menu close the corresponding owned entries. Run settings
travel inside `StartRun`; score queries and native return latches travel inside
`ShowScores`; quest outcomes enter their results screen through its constructor.
The pending request mailboxes and duplicated active/front/menu flags are gone.

Modes are created on first use and cached so later runs keep their existing RNG
progression. Ordinary panels are also cached: the Alien Zoo Keeper board,
score, and timers retain their original process lifetime. Resumption preserves
the result record, sliders, or run while resetting transition/input state.
Refreshing scores reloads records without calling `open()`.

`ScreenTransition` owns the common timeline and its single close request.
Main-menu staggered intervals, 300 ms panels, and the quest-results 100–400 ms
slide retain their distinct timing. Pure animation/layout helpers and shared
chrome functions replace private methods used through unrelated screen objects.
Play Game retains its different Enter and panel-sound behavior.

Controls capture consumes Escape/Enter first. An open dropdown then owns input,
including Escape dismissal; ordinary widgets and Back run afterward. Score
dropdown dismissal also consumes the click, preventing activation of Play
underneath it. Rendering and input use the same optional capture and dropdown
selection values.

## Regression coverage

- Full Controls update and capture rendering for all four player indices.
- Score refresh, persisted preference changes, native return context, selected
  launches, locked quests, and dropdown input consumption.
- Menu → Options → Controls → Back; gameplay → Pause → Options → Controls →
  Back → resume; results → scores → Back without repeating completion effects.
- Exact retained-run identity, screen close counts, failed entry cleanup,
  resource disposal order, lazy mode construction, and persistent secret state.
- Animation interval boundaries, direction, close-request emission, existing
  UI coordinate/render fixtures, and runner quit/screenshot callbacks.

## Validation

`just check && uv build` passed on the final implementation at `f96fae246`
with the updated architecture documentation:

- Python: **2,589 passed, 10 skipped; 135 snapshots passed**.
- Zig: **611/611 tests passed**; ReleaseFast and WASM builds passed.
- Ruff, import contracts, typing, documentation checks, structural rules/tests,
  and the repository's native artifact/closure and matching-regression checks
  passed.
- Source distribution and wheel built successfully.

The final gate used `UV_CACHE_DIR=/private/tmp/crimson-uv-cache` and
`ZIG_GLOBAL_CACHE_DIR=/private/tmp/crimson-review-zig-cache` for writable caches.
The historical report, probes, probe results, and evidence file are unchanged.

The screen journeys use real screen/navigation/update code with mocked Raylib
I/O and graphics allocation; retained gameplay is a test double where noted in
the tests. No new original-game capture or interactive visual playtest was
performed. These checks do not establish additional native instruction parity
or Zig screen feature parity; the implementation changes are in the Python port.
