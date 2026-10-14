from __future__ import annotations

from pathlib import Path

from crimson.persistence import save_status
from crimson.screens.quest_views import QuestsMenuView


def test_quest_select_f1_counts_ignore_untracked_stage5_slots(make_game_state, tmp_path: Path) -> None:
    quest_counts = [0] * int(save_status.QUEST_PLAY_COUNT)
    quest_counts[11] = 7
    quest_counts[51] = 123
    quest_counts[55] = 456
    quest_counts[56] = 789
    quest_counts[60] = 999

    status = save_status.GameStatus.from_data(
        path=Path("game.cfg"),
        data=save_status.GameStatusData(
            mode_play_survival=111,
            mode_play_rush=222,
            mode_play_typo=333,
            mode_play_other=444,
            play_time_ms=0x01020304,
            reserved_seed_words=bytes(range(save_status.RESERVED_SEED_WORDS_BYTE_SIZE)),
            quest_play_counts=tuple(quest_counts),
        ),
        dirty=False,
    )
    state = make_game_state(assets_root=tmp_path, status=status)
    view = QuestsMenuView(state)

    assert view._quest_counts(stage=1, row=0) == (123, 7)
    for row in range(10):
        assert view._quest_counts(stage=5, row=row) is None
