from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.persistence import save_status
from crimson.weapons import WeaponId


def test_game_cfg_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / save_status.GAME_CFG_NAME
    data = save_status.GameStatusData(
        reserved_seed_words=b"crimsonland-test".ljust(save_status.RESERVED_SEED_WORDS_BYTE_SIZE, b"\x00"),
    )

    save_status.save_status(path, data)
    reloaded = save_status.load_status(path)

    assert reloaded.as_data() == data
    assert reloaded.dirty is False


def test_ensure_game_status_raises_on_checksum_mismatch(tmp_path: Path) -> None:
    path = tmp_path / save_status.GAME_CFG_NAME
    path.write_bytes(b"\xFF" * save_status.FILE_SIZE)

    with pytest.raises(ValueError, match="checksum mismatch"):
        save_status.ensure_game_status(tmp_path)


def test_game_status_edit_persists(tmp_path: Path) -> None:
    status = save_status.ensure_game_status(tmp_path)
    assert status.quest_unlock_index == 0
    assert status.quest_unlock_index_full == 0

    status.quest_unlock_index = 12
    status.quest_unlock_index_full = 34
    status.play_time_ms = 0x12345678
    status.increment_mode_play_count_for_mode(GameMode.SURVIVAL)
    status.increment_weapon_usage_slot(5)
    status.increment_quest_play_count(7, delta=2)
    status.save_if_dirty()

    reloaded = save_status.load_status(status.path)
    assert reloaded.quest_unlock_index == 12
    assert reloaded.quest_unlock_index_full == 34
    assert reloaded.play_time_ms == 0x12345678
    assert reloaded.mode_play_count_for_mode(GameMode.SURVIVAL) == 1
    assert reloaded.weapon_usage_count_slot(5) == 1
    assert reloaded.quest_play_count(7) == 2


def test_game_status_weapon_usage_for_weapon_id_handles_untracked_ids() -> None:
    status = save_status.GameStatus.from_data(
        path=Path("game.cfg"),
        data=save_status.default_status_data(),
        dirty=False,
    )

    assert status.increment_weapon_usage_for_weapon_id(WeaponId.PISTOL) == 1
    assert status.weapon_usage_count_for_weapon_id(WeaponId.PISTOL) == 1
    assert status.increment_weapon_usage_for_weapon_id(WeaponId.NUKE_LAUNCHER) is None
    assert status.weapon_usage_count_for_weapon_id(WeaponId.NUKE_LAUNCHER) == 0
