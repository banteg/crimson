from __future__ import annotations

import hashlib
import io
import urllib.request
from pathlib import Path
from typing import cast

import pytest

from crimson import assets_fetch
from crimson.assets_fetch import _download_file, download_missing_paqs, migrate_music_paq
from grim import paq
from grim.console import create_console


class _FakeResponse(io.BytesIO):
    pass


def test_download_file_uses_unique_tempfile(mocker, tmp_path: Path) -> None:
    payload = b"paq payload\n" * 128

    def fake_urlopen(req: object, *, timeout: int) -> _FakeResponse:
        return _FakeResponse(payload)

    mocker.patch.object(urllib.request, "urlopen", side_effect=fake_urlopen)

    original_replace = Path.replace

    def spy_replace(self: Path, target: Path) -> Path:
        return original_replace(self, target)

    replace = mocker.patch.object(Path, "replace", autospec=True, side_effect=spy_replace)

    dest = tmp_path / "crimson.paq"
    _download_file("http://example.invalid/crimson.paq", dest)

    assert dest.read_bytes() == payload
    replace.assert_called_once()
    tmp_source = cast("Path", replace.call_args.args[0])
    assert tmp_source.parent == dest.parent
    assert tmp_source != dest.with_suffix(dest.suffix + ".tmp")


def test_migrate_music_paq_renames_an_earlier_repack_once(tmp_path: Path) -> None:
    paq.write_paq(
        tmp_path / "music.paq",
        [("intro.ogg", b"intro"), ("music/game_tunes.txt", b"snd_addGameTune gt1_ingame.ogg\n")],
    )

    assert migrate_music_paq(tmp_path)
    assert paq.read_paq(tmp_path / "music.paq") == [
        ("music\\intro.ogg", b"intro"),
        ("music\\game_tunes.txt", b"snd_addGameTune gt1_ingame.ogg\n"),
    ]
    assert not migrate_music_paq(tmp_path)
    assert not (tmp_path / "music.paq.tmp").exists()


@pytest.mark.parametrize("installed", [b"old", b"current", b"custom", b"original-release", None])
def test_download_upgrades_only_known_old_art(mocker, tmp_path: Path, installed: bytes | None) -> None:
    old, new = b"old", b"current"
    mocker.patch.object(assets_fetch, "PREVIOUS_CRIMSON_PAQ_SHA256", {hashlib.sha256(old).hexdigest()})
    expected = hashlib.sha256(new).hexdigest()
    mocker.patch.object(assets_fetch, "CRIMSON_PAQ_SHA256", expected)
    dest = tmp_path / "crimson.paq"
    if installed is not None:
        dest.write_bytes(installed)
    request = mocker.patch.object(urllib.request, "urlopen", side_effect=lambda *_args, **_kwargs: _FakeResponse(new))
    results = download_missing_paqs(tmp_path, create_console(tmp_path), names=("crimson.paq",))
    if installed in {old, None}:
        assert len(results) == 1 and results[0].ok
        assert dest.read_bytes() == new
        assert request.call_args.args[0].full_url.endswith(f"crimson.paq?sha256={expected}")
    else:
        assert results == ()
        request.assert_not_called()
        assert dest.read_bytes() == installed


@pytest.mark.parametrize("payload", [b"stale-cache", b"<html>error</html>"])
def test_hash_mismatch_preserves_old_pack_and_removes_temporary_file(mocker, tmp_path: Path, payload: bytes) -> None:
    dest = tmp_path / "crimson.paq"
    dest.write_bytes(b"old")
    mocker.patch.object(urllib.request, "urlopen", side_effect=lambda *_args, **_kwargs: _FakeResponse(payload))
    with pytest.raises(RuntimeError, match="unexpected SHA-256"):
        _download_file("https://example.invalid/crimson.paq", dest, expected_sha256=hashlib.sha256(b"current").hexdigest())
    assert dest.read_bytes() == b"old"
    assert not list(tmp_path.glob("*.tmp"))
