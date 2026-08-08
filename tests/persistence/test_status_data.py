from __future__ import annotations

import hashlib
from pathlib import Path

from crimson.net.deterministic_status import build_lan_deterministic_status, status_data_from_status
from crimson.persistence.save_status import (
    QUEST_PLAY_COUNT,
    RESERVED_SEED_WORDS_BYTE_SIZE,
    WEAPON_USAGE_COUNT,
    GameStatus,
    GameStatusData,
    build_status_blob,
    default_status_data,
    hash_status_data,
)


def test_status_data_from_status_uses_full_typed_payload() -> None:
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

    assert status_data_from_status(status) == data
    assert status_data_from_status(None) == default_status_data()


def test_build_lan_deterministic_status_uses_full_payload() -> None:
    data = GameStatusData(
        quest_unlock_index=7,
        quest_unlock_index_full=9,
        reserved_seed_words=b"\xCD" * int(RESERVED_SEED_WORDS_BYTE_SIZE),
    )

    status = build_lan_deterministic_status(status=data)

    assert status.as_data() == data
    assert status.dirty is False
    assert status.path.name == "crimson-lan-sim-game.cfg"


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
