from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from crimson.game.quest_views import QuestsMenuView
from crimson.persistence import save_status


def test_quest_select_f1_counts_stage5_reads_tail_fields() -> None:
    data = save_status.default_status_data()
    data["mode_play_survival"] = 111
    data["mode_play_rush"] = 222
    data["mode_play_typo"] = 333
    data["mode_play_other"] = 444
    data["game_sequence_id"] = 0x01020304
    data["unknown_tail"] = bytes(range(save_status.UNKNOWN_TAIL_SIZE))

    data["quest_play_counts"][51] = 123
    data["quest_play_counts"][55] = 456
    data["quest_play_counts"][56] = 789
    data["quest_play_counts"][60] = 999

    status = save_status.GameStatus(path=Path("game.cfg"), data=data, dirty=False)
    view = QuestsMenuView(SimpleNamespace(status=status))

    assert view._quest_counts(stage=5, row=0) == (111, 123)
    assert view._quest_counts(stage=5, row=1) == (222, int(status.quest_play_count(52)))
    assert view._quest_counts(stage=5, row=4) == (0x01020304, 456)

    tail_u32 = int.from_bytes(bytes(range(4)), "little")
    assert view._quest_counts(stage=5, row=5) == (tail_u32, 789)

    assert view._quest_counts(stage=5, row=9) == (0, 999)
