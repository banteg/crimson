from __future__ import annotations

from pathlib import Path

from crimson.persistence import save_status
from crimson.screens.quest_views import QuestsMenuView


def test_quest_select_f1_counts_stage5_reads_tail_fields(make_game_state, tmp_path: Path) -> None:
    quest_counts = [0] * int(save_status.QUEST_PLAY_COUNT)
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

    assert view._quest_counts(stage=5, row=0) == (111, 123)
    assert view._quest_counts(stage=5, row=1) == (222, int(status.quest_play_count(52)))
    assert view._quest_counts(stage=5, row=4) == (0x01020304, 456)

    tail_u32 = int.from_bytes(bytes(range(4)), "little")
    assert view._quest_counts(stage=5, row=5) == (tail_u32, 789)

    assert view._quest_counts(stage=5, row=9) == (0, 999)
