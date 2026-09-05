from __future__ import annotations

import hashlib
from pathlib import Path

from crimson.persistence.save_status import (
    QUEST_PLAY_COUNT,
    RESERVED_SEED_WORDS_BYTE_SIZE,
    WEAPON_USAGE_COUNT,
    GameStatus,
    GameStatusData,
    build_status_blob,
    hash_status_data,
)


def test_status_roundtrip_uses_full_typed_payload() -> None:
    weapon_counts = [0] * int(WEAPON_USAGE_COUNT)
    weapon_counts[4] = 99
    quest_counts = [0] * int(QUEST_PLAY_COUNT)
    quest_counts[12] = 7
    data = GameStatusData(
        quest_unlock_index=12,
        quest_unlock_index_full=34,
        weapon_usage_counts=tuple(weapon_counts),
        quest_play_counts=tuple(quest_counts),
        mode_play_survival=11,
        mode_play_rush=22,
        mode_play_typo=33,
        mode_play_other=44,
        play_time_ms=55,
        reserved_seed_words=b"\xAB" * int(RESERVED_SEED_WORDS_BYTE_SIZE),
    )
    status = GameStatus.from_data(path=Path("game.cfg"), data=data, dirty=False)

    assert status.as_data() == data




def test_hash_status_data_hashes_full_blob() -> None:
    quest_counts = [0] * int(QUEST_PLAY_COUNT)
    quest_counts[5] = 123
    data = GameStatusData(
        quest_unlock_index=1,
        quest_unlock_index_full=2,
        quest_play_counts=tuple(quest_counts),
        reserved_seed_words=bytes(range(int(RESERVED_SEED_WORDS_BYTE_SIZE))),
    )

    assert hash_status_data(data) == hashlib.sha256(build_status_blob(data)).hexdigest()


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
    assert load_status(status.path).as_data() == status.as_data()
