from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game.runtime import _require_runtime_assets, _runtime_download_targets


def _touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")


def test_require_runtime_assets_accepts_all_paq_archives(tmp_path: Path) -> None:
    _touch(tmp_path / "crimson.paq")
    _touch(tmp_path / "music.paq")
    _touch(tmp_path / "sfx.paq")

    _require_runtime_assets(tmp_path)


def test_require_runtime_assets_accepts_unpacked_audio_dirs(tmp_path: Path) -> None:
    _touch(tmp_path / "crimson.paq")
    (tmp_path / "music").mkdir()
    (tmp_path / "sfx").mkdir()

    _require_runtime_assets(tmp_path)


def test_require_runtime_assets_requires_crimson_archive(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="crimson\\.paq"):
        _require_runtime_assets(tmp_path)


def test_require_runtime_assets_requires_audio_source_per_pack(tmp_path: Path) -> None:
    _touch(tmp_path / "crimson.paq")
    _touch(tmp_path / "sfx.paq")

    with pytest.raises(FileNotFoundError, match=r"music\.paq \(or music/\)"):
        _require_runtime_assets(tmp_path)


def test_runtime_download_targets_skip_music_when_unpacked_dir_exists(tmp_path: Path) -> None:
    _touch(tmp_path / "crimson.paq")
    (tmp_path / "music").mkdir()

    assert _runtime_download_targets(tmp_path) == ("crimson.paq", "sfx.paq")


def test_runtime_download_targets_include_both_optional_paqs_when_missing(tmp_path: Path) -> None:
    assert _runtime_download_targets(tmp_path) == ("crimson.paq", "music.paq", "sfx.paq")
