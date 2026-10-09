from __future__ import annotations

from pathlib import Path

from crimson.persistence.save_status import (
    QUEST_PLAY_COUNT,
    WEAPON_USAGE_COUNT,
    GameStatus,
)


def test_counter_overflow_remains_serializable(tmp_path: Path) -> None:
    from crimson.game_modes import GameMode
    from crimson.persistence.save_status import load_status

    status = GameStatus(path=tmp_path / "game.cfg", mode_play_survival=0xFFFFFFFF,
                        weapon_usage_counts=(0xFFFFFFFF,) * WEAPON_USAGE_COUNT,
                        quest_play_counts=(0xFFFFFFFF,) * QUEST_PLAY_COUNT)
    assert status.increment_mode_play_count_for_mode(GameMode.SURVIVAL) == 0
    assert status.increment_weapon_usage_slot(0) == 0
    assert status.increment_quest_play_count(0) == 0
    status.save()
    assert load_status(tmp_path / "game.cfg").as_data() == status.as_data()
