# Screen review: navigation, lifecycle, and input ownership

Reviewed on 2026-09-05 at `e4967aed501b6d83c777d2d89d258488274d3b9b`, after the
previous port-review fixes and network removal.

The screens are the next useful architectural target. The four-method `View`
protocol is already adequate. The problems are how navigation, screen lifetime,
transition animation, and input precedence are implemented around it. Five
reproduced bugs illustrate those boundaries.

This is a follow-up report. Production code and the existing test suite are
unchanged. Proposed fixes and refactors below are not implemented.

## Findings

| ID | Priority | Observable behavior | Main cause |
| --- | --- | --- | --- |
| C1 | P2 | Escape exits Controls instead of cancelling capture; Enter exits instead of binding | Parent panel handles navigation before the capturing widget |
| C2 | P2 | Player 1 gets no capture prompt, active highlight, or cancellation hint | Valid index zero is treated as absent |
| C3 | P2 | Updating scores changes the selected quest, removes the highlight, and forgets unsaved preferences | Refresh calls the screen's full `open()` lifecycle |
| C4 | P2 | Returning from score browsing keeps the browsed mode in the originating run's shared config | Navigation preserves the view but not its return context |
| C5 | P2 | “Play a game” opens the general mode picker instead of starting the selected score mode/quest | A generic destination string drops the launch intent |

### C1. A base-class update steals capture input

[ControlsMenuView.update](/Users/banteg/dev/banteg/crimson/src/crimson/screens/panels/controls.py:197)
calls `super().update(dt)` first. The
[base panel](/Users/banteg/dev/banteg/crimson/src/crimson/screens/panels/base.py:149)
turns both Escape and Enter into its Back action. Controls then sees `_closing`
and returns before `_update_rebind_capture` can handle either key.

The headless probe starts a real, armed Fire-binding capture and calls the real
`ControlsMenuView.update` with each key. Both produce `open_options`, with the
capture still active. The explicit Escape-cancels-capture branch is unreachable
through this normal update path. Enter is a valid keyboard binding in the input
code map but cannot reach its capture reader.

Recovered
[controls_menu_update](/Users/banteg/dev/banteg/crimson/tools/match/scratches/controls_menu_update/scratch.cpp:603)
handles Escape inside capture, releases its input lock, and scans other binding
codes including Return. This supports making the active capture consume input
before panel navigation. A deeper panel inheritance tree would make this problem
harder to solve.

### C2. Player 1's active-capture state is rendered as inactive

The two checks at
[controls.py:865](/Users/banteg/dev/banteg/crimson/src/crimson/screens/panels/controls.py:865)
and
[controls.py:900](/Users/banteg/dev/banteg/crimson/src/crimson/screens/panels/controls.py:900)
use `self._rebind_player_index or -1`. Player 1 has index zero, which becomes
`-1`. The corresponding input handler uses `or 0`, so capture can work while its
display says nothing is happening.

The probe calls the real contents renderer while recording text draw requests.
Player 1 emits neither `<press input>` nor the cancellation hint; Player 2 emits
both. The same condition gates the active row color. This is a concrete case
for one optional `RebindCapture(row, player_index, ...)` value instead of several
loosely coupled optional fields and truthiness defaults.

### C3. Refresh accidentally means reopen

The “Update scores” handler at
[view.py:240](/Users/banteg/dev/banteg/crimson/src/crimson/screens/high_scores_view/view.py:240)
calls `self.open()`. Opening clears `_dirty`, the scroll position, and widgets,
then consumes a new request through `resolve_request`. The original request has
already been consumed on entry.

The probe opens quest 1.1 with a highlighted score, uses the real arrow handler
to browse 1.2, changes the date filter through the real widget handler, and
activates Update:

| State | Before Update | After Update |
| --- | --- | --- |
| Selected quest | 1.2 | 1.1 |
| Highlight rank | 4 | absent |
| Unsaved changes | true | false |

Back then makes zero calls to `config.save()`. The changed preferences remain in
memory, but this screen no longer saves them on departure. Another later save
may persist them; this is not a claim that every application shutdown loses them.

There is already a suitable
[`_reload_records()`](/Users/banteg/dev/banteg/crimson/src/crimson/screens/high_scores_view/view.py:356)
operation that retains the current request and clamps scrolling. Use that for
refresh. Reserve entry, resumption, refresh, and starting a new run for distinct
operations.

### C4. A retained screen is not a complete return context

The score widgets
[mutate shared gameplay configuration](/Users/banteg/dev/banteg/crimson/src/crimson/screens/high_scores_view/view.py:487).
The loop's
[Back handling](/Users/banteg/dev/banteg/crimson/src/crimson/game/loop_view.py:304)
only pops a screen; it does not restore mode or quest selection.

The probe uses the real loop, real score screen, and a gameplay test double:
Survival's game-over path opens scores, the mode widget selects Rush, and Back
returns to the original Survival screen. `config.gameplay.mode` remains Rush.
Quest-arrow changes similarly write `config.gameplay.quest_level` without an
originating selection being restored by this return path.

The recovered
[game-over entry](/Users/banteg/dev/banteg/crimson/tools/match/scratches/game_over_screen_update/scratch.cpp:305)
and
[quest-results entry](/Users/banteg/dev/banteg/crimson/tools/match/scratches/quest_results_screen_update/scratch.cpp:619)
save mode, quest stage, and hardcore state before score browsing. The recovered
[score Back handler](/Users/banteg/dev/banteg/crimson/tools/match/scratches/highscore_screen_update/scratch.cpp:539)
restores them. The port needs an explicit return context or score-browser state
separate from the run's launch settings. Preserve native distinctions between
opening scores from Statistics and opening them from a finished run; do not
invent blanket rollback of every preference or player-count field.

### C5. Starting from scores discards the selected launch

At
[view.py:251](/Users/banteg/dev/banteg/crimson/src/crimson/screens/high_scores_view/view.py:251),
every “Play a game” click emits `open_play_game`. Probes for Survival, Rush,
Typ-o, and Quests all produce that action.

Recovered
[highscore_screen_update](/Users/banteg/dev/banteg/crimson/tools/match/scratches/highscore_screen_update/scratch.cpp:473)
starts the selected gameplay mode directly; the quest branch verifies the
selected quest is unlocked. It also initiates the gameplay fade/music transition.

Emit a typed launch request containing the selected mode and, for Quests, its
level. Apply the same launch validation and transition path used by the mode
picker. This is useful consolidation: otherwise each UI recreates selection,
fade, music, statistics, and run setup rules.

## Recommended architecture

### 1. Make navigation the single owner of visible-screen state

`GameLoopView` currently maintains `_active`, `_front_active`, `_front_stack`,
`_menu_active`, `_demo_active`, `_quit_after_demo`, and `state.pause_background`.
Its `update` also implements routing, stack cleanup, music, quest setup, fades,
console handling, telemetry, and demo-trial policy.

Several independent branches repeat close/pop/open assignments. Whether a
screen is pushed or replaced depends on hard-coded action-name sets. Options
always emits `open_pause_menu` on Back; the loop reinterprets that as Main Menu
when no run is active. Unknown strings are silently ignored after the departing
screen may have completed its close animation.

Use one small, concrete navigator owning the current screen and retained return
entries. Model operations such as replace, push, pop, and return-to-menu
explicitly. Derive the gameplay background from the retained run, with the
overlay's entity alpha supplied separately. Keep navigation history and resource
ownership distinguishable: a return target is not necessarily a newly allocated
screen, and opening it must not silently restart its run.

Replace string actions and `GameState.pending_*` mailboxes with a closed set of
typed requests: `StartRun(settings)`, `ShowScores(query, return_context)`,
`ShowQuestResults(outcome)`, `Back`, and ordinary panel destinations. The names
are illustrative, not a proposed framework API. Requests must carry their
payload together, rather than requiring consumers to guess which mutable global
was set beforehand.

### 2. Give enter, resume, and disposal distinct meanings

Stacking currently leaves the previous screen open, and popping normally skips
any lifecycle method. Statistics alone gets a hard-coded `reopen_from_child()`
call in the loop. Game-over and quest-result widgets reset their own closing
state when emitting an action. These particular paths already work; they are
different local solutions to the same missing contract, not additional bugs.

Use an explicit resume operation that preserves the run, score record, or
selection while resetting only the required transition/input state. Initial
entry receives its payload once. Refresh reloads data. Starting again explicitly
starts a new run. Disposal releases owned resources exactly once.

Move application-wide asset/audio lifetime out of `BootView`: its `open()` loads
shared resources and its `close()` unloads them, so the loop intentionally keeps
Boot alive after leaving the boot screen until application shutdown. A normal
screen replacement cannot safely close it. Runtime resource ownership should
outlive the intro independently of whether that view is still retained.

After those semantics are explicit, create gameplay modes when entered instead
of constructing five modes plus Demo up front. This is an ownership simplification;
startup performance has not been benchmarked in this review.

### 3. Share animation and chrome through composition

`PanelMenuView` mixes animation, Back input, audio pumping, background choice,
layout, sign drawing, and content. Play Game inherits it but duplicates its
update loop because Enter must not mean Back. Options copies the base draw
sequence. Other screens rebuild much of the same machinery independently.

A structural search found **21 calls across 11 files** to
`MenuView._ui_element_anim`, passing unrelated view instances as `self` through
the private `_TimelineView` protocol. Pause carries another copy of the animation
formula. These helpers belong in UI modules and should take the timeline value
explicitly.

Extract a small transition value and pure animation/layout helpers. Share panel,
sign, background, and cursor composition as functions. Let each screen's update
state clearly which widget gets input and when Back is allowed. Keep genuinely
different timing profiles: the staggered main-menu items, 300 ms panels, and
quest-results 100–400 ms slide interval must not be normalized into one behavior.
Existing draw/coordinate captures are useful verification fixtures.

### 4. Make input precedence explicit without building a widget framework

For Controls, process capture first, then an open dropdown, then ordinary
widgets and navigation. An explicit consumed result is enough. A small sampled
UI-input value would let tests drive full updates without patching global Raylib
functions; it need not be the deterministic gameplay input format.

Consolidate its three mutually exclusive dropdown booleans into one selection,
and its rebind fields into an optional capture record. Keep binding mutation
separate from rendering. Apply the same approach to High Scores' query/selection state.

The useful smaller pieces already present should remain: `View`, immutable
layout values, `UiButtonState`, the panel drawing functions, and the independent
result calculations. A new universal UI base class would expand the very surface
that caused C1.

### Alternatives and implementation order

| Approach | Assessment |
| --- | --- |
| Keep the current loop and extract branch helpers | Lowest immediate risk; useful first step, but retains duplicated navigation ownership and return-context problems |
| Small typed navigator plus composed panel/input helpers | Recommended; exposes lifetime and return semantics while preserving screen-specific behavior and headless tests |
| Full declarative UI or application-wide immutable reducer | Possible, but a much larger migration with little immediate benefit to native layout/timing parity |

Suggested conventional-commit chunks:

1. Fix C1/C2 and add full Controls update/draw regressions.
2. Fix C3/C4/C5 and test score entry, refresh, selected launch, and return context.
3. Introduce typed navigation requests and migrate every caller, deleting string
   dispatch and pending mailboxes as each cutover completes.
4. Centralize screen ownership/resumption; move shared resource lifetime to the
   runtime owner. Test real navigation journeys and close counts.
5. Extract panel transitions/chrome and explicit widget-input precedence, then
   remove duplicated implementations and private cross-view calls.

Also remove the no-op `_maybe_adopt_menu_ground` helper, which still accepts an
unused view argument, and replace `ViewRunHooks`' optional-method `getattr`
probing with explicit runner callbacks. These are small follow-on deletions, not
reasons to widen the screen protocol.

## Evidence and validation

[probes.py](/Users/banteg/dev/banteg/crimson/analysis/reviews/2026-09-05-screen-review/probes.py)
contains the five reproductions;
[probe-results.json](/Users/banteg/dev/banteg/crimson/analysis/reviews/2026-09-05-screen-review/probe-results.json)
records their outputs. The assertions document the bugs at the reviewed commit
and should become desired-behavior regression tests when fixes are approved.
Raylib I/O, graphics allocation, and console polling are mocked. C4 uses a
gameplay test double with the real navigator and score-widget mutation; it is
not an interactive run or evidence of downstream replay corruption.

The existing focused baseline passed: **100 tests**, covering `tests/screens`,
Controls labels/layout, ground persistence, and start-route smoke tests. These
tests mainly exercise individual screen helpers and direct field setup. Add
full journeys for menu → options → controls → Back, gameplay → pause → options
→ Back → resume, and results → scores → Back / selected launch. Assert input
consumption, settings, active/background ownership, and lifecycle counts as well
as layout and emitted action names.

The native comparisons above are inspections of recovered semantic source and
its recovery notes. No fresh native instruction audit, original-game capture,
interactive visual playtest, or Zig screen audit was performed. Full Python/Zig
gameplay gates were already green at the reviewed commit; this report did not
rerun them because it does not change production code.
