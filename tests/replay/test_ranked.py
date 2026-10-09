from __future__ import annotations

import msgspec
import pytest

from crimson.aim_schemes import AimScheme
from crimson.game_modes import GameMode
from crimson.movement_controls import MovementControlType
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
from crimson.replay.types import REPLAY_FORMAT_VERSION, REPLAY_RULES, Replay, ReplayTick, current_recorder
from crimson.sim.input import PlayerInput
from crimson.sim.run_result import RunOutcome, RunResult
from crimson.sim.run_spec import RunSpec, RunStatus
from grim.geom import Vec2

_SURVIVAL = ranked_run_spec(GameMode.SURVIVAL, seed=0x1234)


def test_the_ranked_profile_ranks_on_its_board() -> None:
    quest = ranked_run_spec(GameMode.QUESTS, seed=1, quest_level=QuestLevel(2, 3), hardcore=True)

    assert unranked_reasons(_SURVIVAL) == unranked_reasons(quest) == []
    assert ranked_board(_SURVIVAL) == "survival"
    assert ranked_board(quest) == "quests-hardcore"
    # Hardcore only changes quests, so Survival has one board.
    assert not ranked_run_spec(GameMode.SURVIVAL, seed=1, hardcore=True).hardcore


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
        ({"player_count": 2}, "players"),
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


def _monitor(run: RunSpec, *inputs: PlayerInput) -> set[str]:
    replay = Replay(
        format_version=REPLAY_FORMAT_VERSION,
        game_version="test",
        rules=REPLAY_RULES,
        recorder=current_recorder(),
        pilot=None,
        run=run,
        result=RunResult(RunOutcome.INCOMPLETE, 0, 0, 0, 0, 0, 0, None, ()),
        ticks=[ReplayTick(inputs=[pack_player_input(inp)]) for inp in inputs],
    )
    monitor = RankedTickMonitor(replay=replay)
    PlaybackDriver(replay, version_mismatch_action=None).run(observer=monitor)
    return monitor.reasons


def _input(move: MovementControlType = MovementControlType.STATIC, aim_scheme: AimScheme = AimScheme.MOUSE, *, aim: Vec2,
           target: Vec2 = Vec2(-1.0, -1.0)) -> PlayerInput:
    return PlayerInput(
        move_mode=move, aim_scheme=aim_scheme, aim=aim,
        move=target if move == MovementControlType.MOUSE_POINT_CLICK else Vec2(),
        move_forward_down=False, move_backward_down=False, turn_left_down=False, turn_right_down=False,
    )


def test_aim_stays_inside_the_ranked_view() -> None:
    # The player starts at the arena centre: a 1024x768 view clamped to the arena shows world y 128..896.
    assert _monitor(_SURVIVAL, _input(aim=Vec2(600.0, 890.0)), _input(aim=Vec2(1.0, 130.0))) == set()
    assert _monitor(_SURVIVAL, _input(aim=Vec2(600.0, 905.0))) == {"aim_out_of_view"}
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
