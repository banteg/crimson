from __future__ import annotations

from pathlib import Path

import pytest

from crimson.persistence import highscores
from crimson.persistence.save_status import ensure_game_status, load_status
from grim import atomic_write
from grim.config import default_crimson_cfg, load_crimson_cfg


@pytest.mark.parametrize("failure_point", ["fsync", "replace"])
def test_failed_replacement_preserves_old_file_and_removes_temporary(tmp_path: Path, mocker, failure_point: str) -> None:
    path = tmp_path / "save.bin"
    path.write_bytes(b"previous save")
    mocker.patch.object(atomic_write.os, failure_point, side_effect=OSError("injected IO failure"))

    with pytest.raises(OSError, match="injected IO failure"):
        atomic_write.atomic_write_bytes(path, b"replacement save")

    assert path.read_bytes() == b"previous save"
    assert list(tmp_path.iterdir()) == [path]


def test_score_encoding_failure_preserves_existing_records(tmp_path: Path, mocker) -> None:
    path = tmp_path / "scores.bin"
    record = highscores.HighScoreRecord.blank(rand_value=123)
    highscores.write_highscore_records(path, [record])
    original = path.read_bytes()
    mocker.patch.object(highscores, "encode_record_payload", side_effect=ValueError("injected encoding failure"))

    with pytest.raises(ValueError, match="injected encoding failure"):
        highscores.write_highscore_records(path, [record])

    assert path.read_bytes() == original
    assert len(highscores.read_highscore_records(path)) == 1


def test_status_stays_dirty_until_replacement_succeeds(tmp_path: Path, mocker) -> None:
    status = ensure_game_status(tmp_path)
    status.quest_unlock_index = 7
    replace = mocker.patch.object(atomic_write.os, "replace", side_effect=OSError("injected IO failure"))
    with pytest.raises(OSError):
        status.save_if_dirty()
    assert status.dirty
    assert load_status(status.path).quest_unlock_index == 0

    mocker.stop(replace)
    status.save_if_dirty()
    assert not status.dirty
    assert load_status(status.path).quest_unlock_index == 7


def test_failed_config_save_preserves_previous_settings(tmp_path: Path, mocker) -> None:
    config = default_crimson_cfg(tmp_path / "crimson.cfg")
    config.save()
    previous_width = config.display.width
    config.display.width = previous_width + 100
    mocker.patch.object(atomic_write.os, "fsync", side_effect=OSError("injected IO failure"))
    with pytest.raises(OSError):
        config.save()
    assert load_crimson_cfg(config.path).display.width == previous_width
