from __future__ import annotations

import msgspec
import pytest

from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.replay.driver.setup import ReplayRunnerError
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.commands import PerkMenuOpenCommand, PerkPickCommand
from crimson.sim.run_result import RunOutcome
from grim.rand import CallerStatic
from tests.support.replay_runner_helpers import (
    ReplayRngTraceRecorder,
    _blank_survival_replay,
    _run_verify_playback,
    finish_replay,
)


def test_survival_runner_tick_rng_trace_observer_emits_draw_rows() -> None:
    replay = finish_replay(_blank_survival_replay(ticks=3, seed=0x1234))
    observer = ReplayRngTraceRecorder(rows_by_tick={})

    _run_verify_playback(
        replay,
        trace_rng=True,
        observer=observer,
    )

    assert sorted(observer.rows_by_tick.keys()) == [0, 1, 2]
    tagged_by_tick: dict[int, list[CallerStatic]] = {}
    for tick_index, draws in sorted(observer.rows_by_tick.items()):
        tagged_callers: list[CallerStatic] = []
        for state_before_u32, value_15, state_after_u32, caller in draws:
            expected_after = (int(state_before_u32) * 214013 + 2531011) & 0xFFFFFFFF
            assert int(state_after_u32) == int(expected_after)
            assert int(value_15) == ((int(state_after_u32) >> 16) & 0x7FFF)
            if caller is not None:
                tagged_callers.append(caller)
        tagged_by_tick[int(tick_index)] = tagged_callers

    assert tagged_by_tick == {
        0: [
            RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE,
            RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_RIGHT_Y,
            RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_TYPE_ROLL,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_OVERRIDE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_SIZE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HEADING,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HEALTH,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_LOW_TINT_G,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_LOW_TINT_B,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_REWARD_BONUS,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_RED,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_GREEN,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_BLUE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_PURPLE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_YELLOW,
            RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED,
        ],
        1: [RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED],
        2: [RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED],
    }


def _with_commands(replay, commands):
    replay.ticks[0] = msgspec.structs.replace(replay.ticks[0], commands=list(commands))
    return replay


def _perk_menu_replay(*ticks: list) -> PlaybackDriver:
    replay = finish_replay(_blank_survival_replay(ticks=len(ticks), seed=0x1234))
    for index, commands in enumerate(ticks):
        replay.ticks[index] = msgspec.structs.replace(replay.ticks[index], commands=list(commands))
    driver = PlaybackDriver(replay)
    driver.world.state.perk_selection.pending_count = 2
    return driver


OPEN = PerkMenuOpenCommand(player_index=0)
PICK = PerkPickCommand(player_index=0, choice_index=0)


def test_survival_runner_picks_on_the_tick_after_the_menu_opens() -> None:
    # The second pick follows the same tick's reopening, as picking and pressing the perk key again does.
    driver = _perk_menu_replay([OPEN], [PICK, OPEN], [PICK])

    for tick in range(3):
        driver.step_tick(tick)

    assert sum(driver.world.state.perks.counts) == 2


@pytest.mark.parametrize(
    "ticks",
    [
        pytest.param([[OPEN, PICK]], id="the tick that opens it"),
        pytest.param([[OPEN], [PICK, PICK]], id="a second pick"),
        pytest.param([[OPEN], [], [PICK]], id="after a cancel"),
    ],
)
def test_survival_runner_rejects_a_pick_the_open_menu_does_not_allow(ticks) -> None:
    driver = _perk_menu_replay(*ticks)

    with pytest.raises(ReplayRunnerError, match="perk_pick without an open perk menu"):
        for tick in range(len(ticks)):
            driver.step_tick(tick)


def test_survival_runner_allows_the_run_down_then_rejects_further_ticks() -> None:
    # The world runs on while the HUD fades out: the end tick and 31 more ticks of 16ms (500ms).
    run_down = finish_replay(_blank_survival_replay(ticks=32, seed=0x1234))
    driver = PlaybackDriver(run_down)
    for player in driver.world.players:
        player.health = 0.0
        player.death_timer = 0.0
    assert driver.run().outcome == RunOutcome.DEATH

    replay = finish_replay(_blank_survival_replay(ticks=33, seed=0x1234))
    driver = PlaybackDriver(replay)
    for player in driver.world.players:
        player.health = 0.0
        player.death_timer = 0.0

    with pytest.raises(
        ReplayRunnerError, match=r"run ended \(death\) at tick 0 and wound down by tick 31 but the replay has 33 ticks",
    ):
        driver.run()
