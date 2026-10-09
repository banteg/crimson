"""The replay viewer over the recorded fixtures: snow (quest 4.10), light dirt (quest 1.1) and dark ground (Survival).

`seek_back` and `straight` (and `seek_ahead` and `straight_ahead`) show the same tick, reached by a seek (a keyframe
and the terrain rebuilt from its copy and the bake log) and by straight play; they should match pixel for pixel.
"""

import datetime as dt
from pathlib import Path

from common import *

FIXTURES = Path("tests/fixtures/replays")
# Two minutes into the Survival run, past plenty of blood and corpses.
SAME_TICK = 7200
LATE_TICK = 20000


def viewer(gs):
    return gs.screens.active


def watch(name):
    def run(gs):
        from crimson.game.navigation import ScreenNavigator
        from crimson.replay import load_replay_file
        from crimson.screens.actions import WatchReplay
        from crimson.screens.replay_viewer import replay_card

        replay = load_replay_file(FIXTURES / f"{name}.crd")
        card = replay_card(replay, name="banteg", day=dt.date(2026, 10, 10))
        ScreenNavigator(gs).navigate(WatchReplay(replay, card.record, 3))

    return ("hook", run)


def prepared(gs):
    """Blocks until the pass has played the whole run."""
    viewer(gs).preparation.wait()


def seek(tick):
    return ("hook", lambda gs: viewer(gs).ask(tick))


def pick_tick(gs):
    return viewer(gs).preparation.picks[0].tick


def bar_at(fraction):
    return lambda gs: (112 + viewer(gs)._pips() * 8 * fraction, 768 - 48 + 26)


s = [*boot(), watch("quest-4.10-completed"), ("wait", 60), ("shot", "snow_playing"), ("hook", prepared)]
s += [("move", bar_at(0.4)), ("wait", 10), ("shot", "snow_bar_hover"), ("key", "KEY_SPACE"), ("wait", 10)]
s += [("shot", "snow_paused"), ("key", "KEY_END"), ("wait", 60), ("move", *IDLE), ("wait", 10), ("shot", "snow_end")]
s += [("key", "KEY_ESCAPE"), ("wait", 30)]

s += [watch("quest-2.10-completed"), ("hook", prepared), ("hook", lambda gs: viewer(gs).ask(pick_tick(gs) - 20))]
s += [("wait", 45), ("shot", "pick_box"), ("key", "KEY_ESCAPE"), ("wait", 30)]

s += [watch("quest-1.1-completed"), ("wait", 300), ("move", bar_at(0.7)), ("wait", 10), ("shot", "dirt_bar")]
s += [("key", "KEY_END"), ("wait", 60), ("shot", "dirt_end"), ("key", "KEY_ESCAPE"), ("wait", 30)]

# Dark ground: the marks, then the same tick by a seek back and by straight play, a few frames on (a shot is of an
# earlier frame).
def straight_to(tick):
    def run(gs):
        player = viewer(gs).player
        player.run(tick - player.tick_index)
        player.settle_hud()

    return ("hook", run)


s += [watch("survival-238852"), ("hook", prepared), seek(20000), ("wait", 5), ("move", bar_at(0.5)), ("wait", 10)]
s += [("shot", "survival_marks"), ("move", *IDLE), ("wait", 200)]
s += [("hook", lambda gs: viewer(gs).seek(SAME_TICK)), ("wait", 4), ("shot", "seek_back")]
s += [("hook", lambda gs: viewer(gs).seek(LATE_TICK)), ("wait", 4), ("shot", "seek_ahead")]
s += [("key", "KEY_ESCAPE"), ("wait", 30), watch("survival-238852"), ("wait", 200), straight_to(SAME_TICK)]
s += [("wait", 4), ("shot", "straight"), straight_to(LATE_TICK), ("wait", 4), ("shot", "straight_ahead")]
STEPS = s
