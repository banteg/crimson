from __future__ import annotations

import msgspec
import pytest

from crimson.aim_schemes import AimScheme
from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.game_version import REPLAY_FORMAT_VERSION, REPLAY_RULES
from crimson.movement_controls import MovementControlType
from crimson.quests.dsl import build_custom_quest
from crimson.quests.level import QuestLevel
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.replay.input_codec import pack_player_input
from crimson.replay.ranked import (
    RankedTickMonitor,
    outcome_reasons,
    ranked_board,
    ranked_run_spec,
    unranked_reasons,
)
from crimson.replay.types import Replay, ReplayTick, current_recorder
from crimson.sim.input import PlayerInput
from crimson.sim.run_result import RunOutcome, RunResult
from crimson.sim.run_spec import RunSpec, RunStatus
from grim.geom import Vec2

_SURVIVAL = ranked_run_spec(GameMode.SURVIVAL, seed=0x1234)
_COOP = ranked_run_spec(GameMode.SURVIVAL, seed=0x1234, player_count=2)
_CUSTOM = build_custom_quest('quest "Test" version 1\nat 1s:\n    spawn alien.fast at center')


def test_the_ranked_profile_ranks_on_its_board() -> None:
    quest = ranked_run_spec(GameMode.QUESTS, seed=1, quest_level=QuestLevel(2, 3), hardcore=True)
    custom = ranked_run_spec(GameMode.QUESTS, seed=1, custom_quest=_CUSTOM, hardcore=True)

    assert unranked_reasons(_SURVIVAL) == unranked_reasons(quest) == unranked_reasons(custom) == []
    assert ranked_board(_SURVIVAL) == "survival"
    assert ranked_board(quest) == "quests-hardcore"
    assert ranked_board(custom) == "quests"
    assert (custom.status.quest_unlock_index, custom.status.quest_unlock_index_hardcore) == (50, 50)
    # Hardcore only changes stock quests, so Survival and custom quests have one board.
    assert not ranked_run_spec(GameMode.SURVIVAL, seed=1, hardcore=True).hardcore
    assert not custom.hardcore


def test_a_co_op_pair_ranks_on_the_co_op_boards() -> None:
    def coop(game_mode: GameMode, **spec) -> RunSpec:
        return ranked_run_spec(game_mode, seed=1, player_count=2, **spec)

    quest = coop(GameMode.QUESTS, quest_level=QuestLevel(2, 3))
    hardcore = coop(GameMode.QUESTS, quest_level=QuestLevel(2, 3), hardcore=True)

    assert unranked_reasons(_COOP) == unranked_reasons(quest) == unranked_reasons(hardcore) == []
    assert [ranked_board(run) for run in (_COOP, quest, hardcore)] == ["survival-coop", "quests-coop", "quests-hardcore-coop"]
    # A custom quest's board and its publishing clear are one player's.
    assert unranked_reasons(coop(GameMode.QUESTS, custom_quest=_CUSTOM)) == ["custom_quest_players"]


def test_either_build_ranks_under_the_same_profile() -> None:
    quest = ranked_run_spec(GameMode.QUESTS, seed=1, quest_level=QuestLevel(2, 3), hardcore=True, cl_build=ClBuild.V1_9_8)
    survival = ranked_run_spec(GameMode.SURVIVAL, seed=1, cl_build=ClBuild.V1_9_8)

    assert (survival.cl_build, quest.cl_build, _SURVIVAL.cl_build) == (ClBuild.V1_9_8, ClBuild.V1_9_8, ClBuild.V1_9_93)
    # The build picks the boards' build, not the board, and every other rule holds as for 1.9.93.
    assert unranked_reasons(survival) == unranked_reasons(quest) == []
    assert [ranked_board(survival), ranked_board(quest)] == ["survival", "quests-hardcore"]
    assert unranked_reasons(msgspec.structs.replace(survival, detail_preset=3, preserve_bugs=True)) == ["original_rules", "detail_preset"]


def test_a_quest_plays_on_the_save_that_unlocked_it() -> None:
    normal = ranked_run_spec(GameMode.QUESTS, seed=1, quest_level=QuestLevel(2, 3))
    hardcore = ranked_run_spec(GameMode.QUESTS, seed=1, quest_level=QuestLevel(2, 3), hardcore=True)

    assert (normal.status.quest_unlock_index, normal.status.quest_unlock_index_hardcore) == (12, 0)
    assert (hardcore.status.quest_unlock_index, hardcore.status.quest_unlock_index_hardcore) == (50, 12)
    # Survival's save, with every quest done, is not a quest's.
    assert unranked_reasons(msgspec.structs.replace(normal, status=_SURVIVAL.status)) == ["unlocks"]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"game_mode_id": GameMode.RUSH}, "mode"),
        ({"player_count": 3}, "players"),
        ({"preserve_bugs": True}, "original_rules"),
        ({"detail_preset": 3}, "detail_preset"),
        ({"violence_disabled": 1}, "violence_disabled"),
        ({"friendly_fire": True}, "friendly_fire"),
        ({"hardcore": True}, "hardcore"),
        ({"quest_fail_retry_count": 2}, "quest_retry"),
        ({"status": RunStatus(quest_unlock_index=12, quest_unlock_index_hardcore=50)}, "unlocks"),
        ({"status": RunStatus(quest_unlock_index=50, quest_unlock_index_hardcore=50, weapon_usage_counts=(1,) * 53)}, "weapon_usage"),
    ],
)
def test_each_departure_from_the_profile_has_its_reason(change: dict, reason: str) -> None:
    assert unranked_reasons(msgspec.structs.replace(_SURVIVAL, **change)) == [reason]


def test_only_finished_runs_rank() -> None:
    def result(outcome: RunOutcome) -> RunResult:
        return RunResult(outcome, 0, 0, 0, 0, 0, 0, None, ())

    quest = ranked_run_spec(GameMode.QUESTS, seed=1, quest_level=QuestLevel(1, 1))
    assert outcome_reasons(_SURVIVAL, result(RunOutcome.DEATH)) == []
    assert outcome_reasons(_SURVIVAL, result(RunOutcome.INCOMPLETE)) == ["unfinished"]
    assert outcome_reasons(quest, result(RunOutcome.QUEST_COMPLETED)) == []
    assert outcome_reasons(quest, result(RunOutcome.DEATH)) == ["unfinished"]


def _replay(run: RunSpec, *ticks: list[PlayerInput]) -> Replay:
    return Replay(
        format_version=REPLAY_FORMAT_VERSION,
        game_version="test",
        rules=REPLAY_RULES,
        recorder=current_recorder(),
        pilot=None,
        seat_keys=None,
        run=run,
        result=RunResult(RunOutcome.INCOMPLETE, 0, 0, 0, 0, 0, 0, None, ()),
        ticks=[ReplayTick(inputs=[pack_player_input(inp) for inp in inputs]) for inputs in ticks],
    )


def _monitor_ticks(run: RunSpec, *ticks: list[PlayerInput]) -> set[str]:
    replay = _replay(run, *ticks)
    monitor = RankedTickMonitor(replay=replay)
    PlaybackDriver(replay, version_mismatch_action=None).run(observer=monitor)
    return monitor.reasons


def _monitor(run: RunSpec, *inputs: PlayerInput) -> set[str]:
    return _monitor_ticks(run, *([inp] for inp in inputs))


def _input(move: MovementControlType = MovementControlType.STATIC, aim_scheme: AimScheme = AimScheme.MOUSE, *, aim: Vec2,
           target: Vec2 = Vec2(-1.0, -1.0), walk: Vec2 = Vec2()) -> PlayerInput:
    return PlayerInput(
        move_mode=move, aim_scheme=aim_scheme, aim=aim,
        move=target if move == MovementControlType.MOUSE_POINT_CLICK else walk,
        move_forward_down=False, move_backward_down=False, turn_left_down=False, turn_right_down=False,
    )


def test_aim_stays_inside_the_ranked_view() -> None:
    # The player starts at the arena centre: a 1024x768 view clamped to the arena shows world y 128..896,
    # with a 96-unit margin for screen shake and a multi-tick frame of movement.
    assert _monitor(_SURVIVAL, _input(aim=Vec2(600.0, 990.0)), _input(aim=Vec2(1.0, 35.0))) == set()
    assert _monitor(_SURVIVAL, _input(aim=Vec2(600.0, 1000.0))) == {"aim_out_of_view"}
    # Pad reach is the stick's, at most `1 * 96 + 42`.
    assert _monitor(_SURVIVAL, _input(MovementControlType.DUAL_ACTION_PAD, AimScheme.DUAL_ACTION_PAD, aim=Vec2(0.0, 138.0))) == set()
    assert _monitor(_SURVIVAL, _input(MovementControlType.DUAL_ACTION_PAD, AimScheme.DUAL_ACTION_PAD, aim=Vec2(0.0, 150.0))) == {
        "aim_out_of_view",
    }
    # A point-click target comes from the same cursor.
    point_click = MovementControlType.MOUSE_POINT_CLICK
    assert _monitor(_SURVIVAL, _input(point_click, aim=Vec2(600.0, 600.0), target=Vec2(512.0, 1000.0))) == {"aim_out_of_view"}


def test_computer_controls_never_rank() -> None:
    assert _monitor(_SURVIVAL, _input(aim_scheme=AimScheme.COMPUTER, aim=Vec2())) == {"controls"}
    assert _monitor(_SURVIVAL, _input(MovementControlType.COMPUTER, aim=Vec2(600.0, 600.0))) == {"controls"}


_IDLE = _input(aim=Vec2(512.0, 512.0))
# Player two walks to the arena's bottom edge, so the co-op camera, between the players, scrolls past player one's.
_WALK_APART = [[_IDLE, _input(MovementControlType.DUAL_ACTION_PAD, aim=Vec2(512.0, 512.0), walk=Vec2(0.0, 1.0))]] * 300


def test_every_co_op_player_aims_inside_the_view_around_the_pair() -> None:
    # The pair's view shows world y 256..1024; player one's own would show 128..896.
    assert _monitor_ticks(_COOP, *_WALK_APART, [_input(aim=Vec2(600.0, 1000.0)), _IDLE]) == set()
    assert _monitor_ticks(_COOP, *_WALK_APART, [_input(aim=Vec2(600.0, 150.0)), _IDLE]) == {"aim_out_of_view"}
    assert _monitor_ticks(_COOP, *_WALK_APART, [_IDLE, _input(aim=Vec2(600.0, 150.0))]) == {"aim_out_of_view"}
    assert _monitor_ticks(_COOP, [_IDLE, _input(aim_scheme=AimScheme.COMPUTER, aim=Vec2())]) == {"controls"}


def _coop_at_edge(
    *ticks: list[PlayerInput], dead_from_start: tuple[int, ...] = (), dead_after_first_tick: tuple[int, ...] = (),
) -> set[str]:
    """Player two stands at the arena's bottom edge while player one starts in the centre."""

    replay = _replay(_COOP, *ticks)
    driver = PlaybackDriver(replay, version_mismatch_action=None)
    monitor = RankedTickMonitor(replay=replay)
    players = driver.world.players
    players[1].pos = Vec2(512.0, 1000.0)
    for index in dead_from_start:
        players[index].health = 0.0
    driver.walk_ticks(stop_tick=1, observer=monitor)
    for index in dead_after_first_tick:
        players[index].health = 0.0
    driver.walk_ticks(start_tick=1, observer=monitor)
    return monitor.reasons


# Player one aims near player two on the third tick: inside the pair's view, outside player one's own.
_EDGE_AIM = ([_IDLE, _IDLE], [_IDLE, _IDLE], [_input(aim=Vec2(600.0, 1000.0)), _IDLE])


def test_the_co_op_camera_follows_the_living_players() -> None:
    assert _coop_at_edge(*_EDGE_AIM) == set()
    # A dead player leaves the camera to the living one, centred on player one again.
    assert _coop_at_edge(*_EDGE_AIM, dead_from_start=(1,)) == {"aim_out_of_view"}
    assert _coop_at_edge(*_EDGE_AIM, dead_after_first_tick=(1,)) == {"aim_out_of_view"}
    # With nobody alive the camera stays where the pair left it.
    assert _coop_at_edge(*_EDGE_AIM, dead_after_first_tick=(0, 1)) == set()


def test_each_co_op_player_holds_their_own_point_click_target() -> None:
    point_click = MovementControlType.MOUSE_POINT_CLICK
    # Both targets are clicked inside the pair's view, which shows world y 256..1024; only player one's
    # lies outside player one's own view.
    held = [
        _input(point_click, aim=Vec2(512.0, 512.0), target=Vec2(600.0, 1020.0)),
        _input(point_click, aim=Vec2(512.0, 512.0), target=Vec2(512.0, 900.0)),
    ]
    # Player two's death recentres the camera on player one, whose held target is then out of view: a target
    # is checked when clicked, and player two's click in between is not player one's.
    assert _coop_at_edge(held, held, held, dead_after_first_tick=(1,)) == set()
    # Player one clicking it anew, once the camera has moved, is out of view.
    no_target = _input(point_click, aim=Vec2(512.0, 512.0))
    assert _coop_at_edge(held, held, [no_target, held[1]], held, dead_after_first_tick=(1,)) == {"aim_out_of_view"}
