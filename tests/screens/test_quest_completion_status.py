from __future__ import annotations

import msgspec
import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestMode
from crimson.perks import PerkId
from crimson.persistence.save_status import GAME_CFG_NAME, GameStatus, load_status
from crimson.quests.level import QuestLevel
from crimson.quests.status import tracked_quest_completed_counter_index
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.screens.actions import StartRun
from crimson.screens.quest_views.quest_failed import QuestFailedView
from crimson.screens.quest_views.quest_results import QuestResultsView
from crimson.sim.run_spec import RunSpec
from grim.raylib_api import rl
from tests.support.replay_runner_helpers import idle_replay

LEVEL = QuestLevel(1, 1)
_completed = tracked_quest_completed_counter_index(LEVEL)
assert _completed is not None
COMPLETED: int = _completed


def _start_cleared_quest(loop: GameLoopView) -> QuestMode:
    """Start 1.1 from the loop and empty its spawn table, so the quest goes idle-complete on the next tick."""

    loop.navigation.navigate(StartRun(GameMode.QUESTS, LEVEL))
    run = loop.state.screens.gameplay
    assert isinstance(run, QuestMode)
    spawn = run._quest_spawn_state
    spawn.spawn_entries = tuple(msgspec.structs.replace(entry, count=0) for entry in spawn.spawn_entries)
    return run


def _play_until(loop: GameLoopView, screen_type: type, *, stop=lambda: False) -> None:
    for _ in range(600):
        if isinstance(loop.state.screens.active, screen_type) or stop():
            return
        loop.update(1.0 / 60.0)
    raise AssertionError(f"the loop never reached {screen_type.__name__}")


def _saved(loop: GameLoopView) -> GameStatus:
    return load_status(loop.state.base_dir / GAME_CFG_NAME)


def test_completion_is_counted_once_and_saved_before_the_results(loop) -> None:
    run = _start_cleared_quest(loop)
    _play_until(loop, QuestResultsView, stop=lambda: run._quest_spawn_state.completed)
    # `quest_mode_update` saved the status on the `timer > 2500` frame, before the results open.
    assert run._quest_spawn_state.completed
    assert (_saved(loop).quest_play_count(COMPLETED), _saved(loop).quest_unlock_index) == (1, 1)
    _play_until(loop, QuestResultsView)
    for _ in range(30):
        loop.update(1.0 / 60.0)
    status = loop.state.status
    assert (status.quest_play_count(COMPLETED), status.quest_unlock_index, status.quest_unlock_index_hardcore) == (1, 1, 0)
    assert _saved(loop).as_data() == status.as_data()


def test_death_after_the_transition_completes_keeps_completion_and_unlock(loop) -> None:
    loop.state.config.gameplay.hardcore = True
    run = _start_cleared_quest(loop)
    spawn = run._quest_spawn_state
    # The death animation outlasts the transition's last 500 ms, as in native.
    _play_until(loop, QuestFailedView, stop=lambda: spawn.completion_transition_ms > 2000.0)
    run.world.players[0].health = 0.0
    _play_until(loop, QuestFailedView)
    saved = _saved(loop)
    assert (saved.quest_play_count(COMPLETED), saved.quest_unlock_index, saved.quest_unlock_index_hardcore) == (1, 1, 1)


def test_quest_completion_takes_over_the_pending_pause_fade(loop, mocker) -> None:
    run = _start_cleared_quest(loop)
    _play_until(loop, QuestResultsView, stop=lambda: run._quest_spawn_state.completion_transition_ms > 2400)
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_ESCAPE)
    loop.update(1 / 60)
    mocker.patch.object(rl, "is_key_pressed", return_value=False)

    # The quest finishes during the existing fade. Dispatch on its original 32nd tick.
    for _ in range(30):
        loop.update(1 / 60)
    assert loop.state.screens.active is run
    assert _saved(loop).quest_unlock_index == 1
    loop.update(1 / 60)
    assert isinstance(loop.state.screens.active, QuestResultsView)


@pytest.mark.parametrize("ticks_into_fade", [0, 12], ids=["terminal-tick", "during-run-down"])
def test_quest_run_down_resumes_after_a_perk_pick(loop, mocker, ticks_into_fade) -> None:
    run = _start_cleared_quest(loop)
    submit = mocker.patch.object(loop.state.replay_saver, "submit")
    selection = run.state.perk_selection
    selection.pending_count = 1
    selection.choices = [PerkId.SHARPSHOOTER] * 7
    selection.choices_dirty = False
    initial_offer = msgspec.structs.replace(selection)
    _play_until(loop, QuestResultsView, stop=lambda: run._quest_spawn_state.completion_transition_ms > 2500)
    recorder = run._replay_recorder
    assert recorder is not None
    terminal_tick = recorder.tick_index
    for _ in range(ticks_into_fade):
        loop.update(1 / 60)
    pressed = {rl.KeyboardKey.KEY_SPACE}
    mocker.patch.object(rl, "is_key_pressed", side_effect=pressed.__contains__)
    loop.update(1 / 60)
    pressed.clear()
    assert run._perk_menu.open
    assert run._quest_spawn_state.completed
    for _ in range(12):
        loop.update(0.1)
    assert recorder.tick_index == terminal_tick + ticks_into_fade + 1
    pressed.add(rl.KeyboardKey.KEY_SPACE)
    loop.update(1 / 60)
    pressed.clear()
    _play_until(loop, QuestResultsView)
    assert selection.pending_count == 0
    assert PerkId.SHARPSHOOTER in run.state.perks
    replay = submit.call_args.args[0].replay
    assert len(replay.ticks) == terminal_tick + 32  # 500 ms, at 16 whole ms per tick.
    driver = PlaybackDriver(replay, spawn_entries=())
    driver.world.state.perk_selection = initial_offer
    assert driver.run() == replay.result


def test_perk_request_on_the_last_run_down_tick_goes_straight_to_results(loop, mocker) -> None:
    run = _start_cleared_quest(loop)
    run.state.perk_selection.pending_count = 1
    _play_until(loop, QuestResultsView, stop=lambda: run._quest_spawn_state.completion_transition_ms > 2500)
    for _ in range(31):
        loop.update(1 / 60)
    mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_SPACE)
    loop.update(1 / 60)

    assert run.state.perk_selection.choices  # The simulation prepared the offer on its last tick.
    assert not run._perk_menu.active
    assert isinstance(loop.state.screens.active, QuestResultsView)


def test_death_before_the_transition_ends_counts_the_completion_without_saving(loop) -> None:
    run = _start_cleared_quest(loop)
    spawn = run._quest_spawn_state
    _play_until(loop, QuestFailedView, stop=lambda: spawn.completion_transition_ms > 100.0)
    run.world.players[0].health = 0.0
    _play_until(loop, QuestFailedView)
    status = loop.state.status
    # The count is in memory for the next save; the unlock never happened.
    assert (status.quest_play_count(COMPLETED), status.quest_unlock_index) == (1, 0)
    assert _saved(loop).quest_play_count(COMPLETED) == 0


def test_replay_playback_does_the_bookkeeping_without_writing_status(mocker) -> None:
    # An empty spawn table completes at tick 152; the run-down ends the replay at tick 183.
    replay = idle_replay(184, run=RunSpec(game_mode_id=GameMode.QUESTS, seed=0x1234, quest_level=LEVEL))
    save = mocker.spy(GameStatus, "save")
    driver = PlaybackDriver(replay, warn_on_version_mismatch=False, spawn_entries=())

    driver.run()

    status = driver.session.world.state.status
    assert (status.quest_play_count(COMPLETED), status.quest_unlock_index) == (1, 1)
    save.assert_not_called()
