from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.leaderboard import Leaderboard, OnlineScore
from crimson.quests.level import QuestLevel
from crimson.screens.actions import ScoreQuery
from crimson.screens.high_scores_view.records import load_records


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
    leaderboard.scores[("quests-hardcore", "2.3")] = [_score("solo")]
    leaderboard.scores[("quests-hardcore-coop", "2.3")] = [_score("pair")]
    state.leaderboard = leaderboard

    records = load_records(state, ScoreQuery(GameMode.QUESTS, QuestLevel(2, 3)))

    assert [record.name() for record in records] == names
