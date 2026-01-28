from __future__ import annotations

from crimson.persistence import save_status


def test_game_cfg_roundtrip(tmp_path) -> None:
    path = tmp_path / save_status.GAME_CFG_NAME
    data = save_status.default_status_data()
    data["unknown_tail"] = b"crimsonland-test".ljust(save_status.UNKNOWN_TAIL_SIZE, b"\x00")
    decoded = save_status.build_status_blob(data)
    save_status.save_status(path, decoded)
    blob = save_status.load_status(path)
    assert blob.checksum_valid
    assert blob.decoded == decoded


def test_ensure_game_status_regenerates_on_checksum_mismatch(tmp_path) -> None:
    path = tmp_path / save_status.GAME_CFG_NAME
    path.write_bytes(b"\xFF" * save_status.FILE_SIZE)
    status = save_status.ensure_game_status(tmp_path)
    assert status.path == path
    blob = save_status.load_status(path)
    assert blob.checksum_valid


def test_game_status_edit_persists(tmp_path) -> None:
    status = save_status.ensure_game_status(tmp_path)
    assert status.quest_unlock_index == 0
    assert status.quest_unlock_index_full == 0
    status.quest_unlock_index = 12
    status.quest_unlock_index_full = 34
    status.game_sequence_id = 0x12345678
    status.increment_mode_play_count("survival")
    status.increment_weapon_usage(5)
    status.increment_quest_play_count(7, delta=2)
    status.save_if_dirty()

    reloaded = save_status.load_status(status.path)
    assert reloaded.checksum_valid
    status2 = save_status.GameStatus(path=status.path, data=save_status.parse_status_blob(reloaded.decoded))
    assert status2.quest_unlock_index == 12
    assert status2.quest_unlock_index_full == 34
    assert status2.game_sequence_id == 0x12345678
    assert status2.mode_play_count("survival") == 1
    assert status2.weapon_usage_count(5) == 1
    assert status2.quest_play_count(7) == 2
