from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import msgspec
import pytest
from typer.testing import CliRunner

from crimson.cli import save as save_cli
from crimson.cli.app import app
from crimson.persistence import save_status
from crimson.quests.level import QUEST_COUNT
from grim import atomic_write


def _populated_save(base_dir: Path) -> tuple[Path, save_status.GameStatusData]:
    path = base_dir / save_status.GAME_CFG_NAME
    data = save_status.GameStatusData(
        quest_unlock_index=12,
        quest_unlock_index_hardcore=3,
        weapon_usage_counts=tuple(range(save_status.WEAPON_USAGE_COUNT)),
        quest_play_counts=tuple(range(save_status.QUEST_PLAY_COUNT)),
        mode_play_survival=123,
        mode_play_rush=45,
        mode_play_typo=67,
        mode_play_other=89,
        play_time_ms=0x12345678,
        reserved_seed_words=b"preserve these!!",
    )
    save_status.save_status(path, data)
    return path, data


@pytest.mark.parametrize("directory_option", ["--base-dir", "--runtime-dir"])
def test_unlock_backs_up_exact_save_and_preserves_other_progress(tmp_path: Path, directory_option: str) -> None:
    path, data = _populated_save(tmp_path)
    before = path.read_bytes()
    scores = tmp_path / "scores.dat"
    scores.write_bytes(b"existing high scores")

    result = CliRunner().invoke(app, ["save", "unlock", directory_option, str(tmp_path)])

    assert result.exit_code == 0, result.output
    backups = list(tmp_path.glob("game.cfg.*.bak"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == before
    assert str(backups[0]) in result.output
    assert save_status.load_status(path).as_data() == msgspec.structs.replace(
        data, quest_unlock_index=QUEST_COUNT, quest_unlock_index_hardcore=QUEST_COUNT,
    )
    assert scores.read_bytes() == b"existing high scores"


def test_already_unlocked_save_is_not_written_or_backed_up_again(tmp_path: Path) -> None:
    path, _ = _populated_save(tmp_path)
    args = ["save", "unlock", "--base-dir", str(tmp_path)]
    runner = CliRunner()
    assert runner.invoke(app, args).exit_code == 0
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in tmp_path.iterdir()}

    result = runner.invoke(app, args)

    assert result.exit_code == 0, result.output
    assert "Already fully unlocked" in result.output
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in tmp_path.iterdir()} == before
    assert save_status.load_status(path).quest_unlock_index == QUEST_COUNT


def test_a_later_unlock_never_overwrites_an_earlier_backup(tmp_path: Path) -> None:
    path, data = _populated_save(tmp_path)
    before = path.read_bytes()
    runner = CliRunner()
    args = ["save", "unlock", "--base-dir", str(tmp_path)]
    assert runner.invoke(app, args).exit_code == 0
    first_backup = next(tmp_path.glob("game.cfg.*.bak"))
    save_status.save_status(path, msgspec.structs.replace(data, quest_unlock_index=25))
    second_before = path.read_bytes()

    result = runner.invoke(app, args)

    assert result.exit_code == 0, result.output
    assert first_backup.read_bytes() == before
    backups = set(tmp_path.glob("game.cfg.*.bak"))
    assert len(backups) == 2
    assert (backups - {first_backup}).pop().read_bytes() == second_before


def test_missing_save_is_not_created(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["save", "unlock", "--base-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "No save" in result.output
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("contents", [b"invalid", b"\xff" * save_status.FILE_SIZE])
def test_invalid_save_is_not_changed_or_backed_up(tmp_path: Path, contents: bytes) -> None:
    path = tmp_path / save_status.GAME_CFG_NAME
    path.write_bytes(contents)
    result = CliRunner().invoke(app, ["save", "unlock", "--base-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "Could not read save" in result.output
    assert path.read_bytes() == contents
    assert list(tmp_path.iterdir()) == [path]


def test_backup_creation_failure_leaves_save_untouched(tmp_path: Path, mocker) -> None:
    path, _ = _populated_save(tmp_path)
    before = path.read_bytes()
    mocker.patch.object(save_cli.tempfile, "NamedTemporaryFile", side_effect=PermissionError("read only"))
    result = CliRunner().invoke(app, ["save", "unlock", "--base-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "Could not back up save" in result.output
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("failure", ["copy", "flush"])
def test_incomplete_backup_is_removed_and_save_untouched(tmp_path: Path, mocker, failure: str) -> None:
    path, _ = _populated_save(tmp_path)
    before = path.read_bytes()

    def fail_copy(source, backup):
        backup.write(source.read(10))
        raise OSError("disk full")

    if failure == "copy":
        mocker.patch.object(save_cli.shutil, "copyfileobj", side_effect=fail_copy)
    else:
        mocker.patch.object(save_cli.os, "fsync", side_effect=OSError("flush failed"))
    result = CliRunner().invoke(app, ["save", "unlock", "--base-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "Save was not changed" in result.output
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_save_replacement_failure_preserves_backup_and_original(tmp_path: Path, mocker) -> None:
    path, _ = _populated_save(tmp_path)
    before = path.read_bytes()
    mocker.patch.object(atomic_write.os, "replace", side_effect=PermissionError("read only"))
    result = CliRunner().invoke(app, ["save", "unlock", "--base-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "Backup preserved" in result.output
    assert path.read_bytes() == before
    backup = next(tmp_path.glob("game.cfg.*.bak"))
    assert backup.read_bytes() == before
    assert set(tmp_path.iterdir()) == {path, backup}


def test_default_directory_honors_runtime_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path, _ = _populated_save(tmp_path)
    before = path.read_bytes()
    monkeypatch.setenv("CRIMSON_RUNTIME_DIR", str(tmp_path))
    result = subprocess.run(
        [sys.executable, "-c", "from crimson.cli import main; main(['save', 'unlock'])"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert save_status.load_status(path).quest_unlock_index == QUEST_COUNT
    assert next(tmp_path.glob("game.cfg.*.bak")).read_bytes() == before
