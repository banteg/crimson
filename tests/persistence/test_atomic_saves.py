from __future__ import annotations

from pathlib import Path

import pytest

from crimson.persistence.save_status import GAME_CFG_NAME, ensure_game_status, load_status
from grim import atomic_write


@pytest.mark.parametrize("failure_point", ["fsync", "replace"])
def test_failed_replacement_preserves_old_file_and_removes_temporary(tmp_path: Path, mocker, failure_point: str) -> None:
    path = tmp_path / "save.bin"
    path.write_bytes(b"previous save")
    mocker.patch.object(atomic_write.os, failure_point, side_effect=OSError("injected IO failure"))

    with pytest.raises(OSError, match="injected IO failure"):
        atomic_write.atomic_write_bytes(path, b"replacement save")

    assert path.read_bytes() == b"previous save"
    assert list(tmp_path.iterdir()) == [path]


def test_status_stays_dirty_until_replacement_succeeds(tmp_path: Path, mocker) -> None:
    status = ensure_game_status(tmp_path)
    status.quest_unlock_index = 7
    replace = mocker.patch.object(atomic_write.os, "replace", side_effect=OSError("injected IO failure"))
    with pytest.raises(OSError):
        status.save_if_dirty()
    assert status.dirty
    assert load_status(tmp_path / GAME_CFG_NAME).quest_unlock_index == 0

    mocker.stop(replace)
    status.save_if_dirty()
    assert not status.dirty
    assert load_status(tmp_path / GAME_CFG_NAME).quest_unlock_index == 7
