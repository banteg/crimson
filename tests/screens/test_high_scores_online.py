from __future__ import annotations

import pytest

from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.leaderboard import Leaderboard, OnlineScore
from crimson.persistence.highscores import HighScoreRecord, ScoreTable, append_highscore_records
from crimson.quests.level import QuestLevel
from crimson.screens.actions import ScoreQuery
from crimson.screens.high_scores_view.records import load_records, online_board


def _score(name: str) -> OnlineScore:
    return OnlineScore(
        name=name, score=60000, elapsed_ms=90000, experience=500, most_used_weapon_id=1,
        shots_fired=0, shots_hit=0, kills=0, accepted_at=0,
    )


@pytest.mark.parametrize(("player_count", "names"), [(1, ["solo"]), (2, ["pair"]), (3, [])])
def test_a_table_shows_the_board_for_its_player_count(make_game_state, tmp_path, player_count, names) -> None:
    state = make_game_state()
    state.config.gameplay.player_count = player_count
    state.config.gameplay.hardcore = True
    state.config.profile.show_internet_scores = True
    leaderboard = Leaderboard(tmp_path, url="https://crimson.test/api", transport=lambda *_: (200, {}))
    leaderboard.scores[("quests-hardcore", "2.3", ClBuild.V1_9_93)] = [_score("solo")]
    leaderboard.scores[("quests-hardcore-coop", "2.3", ClBuild.V1_9_93)] = [_score("pair")]
    state.leaderboard = leaderboard

    records = load_records(state, ScoreQuery(GameMode.QUESTS, QuestLevel(2, 3)))

    assert [record.name for record in records] == names


def test_1_9_8_tables_show_their_own_runs_and_1_9_8_board(make_game_state, tmp_path) -> None:
    state = make_game_state()
    state.cl_build = ClBuild.V1_9_8
    state.config.profile.show_internet_scores = True
    leaderboard = Leaderboard(tmp_path, url="https://crimson.test/api", transport=lambda *_: (200, {}))
    leaderboard.scores[("survival", "", ClBuild.V1_9_93)] = [_score("verified 1.9.93")]
    leaderboard.scores[("survival", "", ClBuild.V1_9_8)] = [_score("verified 1.9.8")]
    state.leaderboard = leaderboard
    append_highscore_records(state.base_dir, [
        HighScoreRecord(name="1.9.93 run", game_mode_id=GameMode.SURVIVAL),
        HighScoreRecord(name="1.9.8 run", game_mode_id=GameMode.SURVIVAL, cl_build=ClBuild.V1_9_8),
    ])
    request = ScoreQuery(GameMode.SURVIVAL)

    records = load_records(state, request)

    assert online_board(state, request) == ("survival", "", ClBuild.V1_9_8)
    assert sorted(record.name for record in records) == ["1.9.8 run", "verified 1.9.8"]
    # The received run is the 1.9.8 table's, as its card names it, like the run saved there.
    table = ScoreTable.for_config(state.config, cl_build=ClBuild.V1_9_8, game_mode_id=GameMode.SURVIVAL)
    assert all(table.holds(record) for record in records)
