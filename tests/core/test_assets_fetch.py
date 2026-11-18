from __future__ import annotations

import hashlib
import io
import urllib.request
from pathlib import Path

import pytest

from crimson import assets_fetch
from crimson.assets_fetch import _download_file, download_missing_paqs, migrate_music_paq
from crimson.runtime_boot import boot_runtime
from grim import paq
from grim.console import create_console


class _FakeResponse(io.BytesIO):
    pass


def test_overlapping_downloads_stage_separate_files_for_the_same_destination(mocker, tmp_path: Path) -> None:
    dest = tmp_path / "crimson.paq"
    url = "http://example.invalid/crimson.paq"
    mocker.patch.object(urllib.request, "urlopen", side_effect=[io.BytesIO(b"first"), io.BytesIO(b"second")])
    staged_paths: list[Path] = []
    replace = Path.replace

    def publish(staged: Path, target: Path) -> Path:
        assert staged.parent == dest.parent
        assert staged not in staged_paths
        staged_paths.append(staged)
        if len(staged_paths) == 1:
            # Let the second download finish while the first is waiting to publish.
            _download_file(url, dest)
            assert dest.read_bytes() == b"second"
        return replace(staged, target)

    mocker.patch.object(Path, "replace", autospec=True, side_effect=publish)
    _download_file(url, dest)

    assert len(staged_paths) == 2
    assert dest.read_bytes() == b"first"
    assert list(tmp_path.iterdir()) == [dest]


def test_migrate_music_paq_renames_an_earlier_repack_once(mocker, tmp_path: Path) -> None:
    paq.write_paq(
        tmp_path / "music.paq",
        [("intro.ogg", b"intro"), ("music/game_tunes.txt", b"snd_addGameTune gt1_ingame.ogg\n")],
    )

    source = (tmp_path / "music.paq").read_bytes()
    expected = paq.build_entries([("music\\intro.ogg", b"intro"), ("music\\game_tunes.txt", b"snd_addGameTune gt1_ingame.ogg\n")])
    mocker.patch.dict(assets_fetch.ART_VERSION, legacy_music=hashlib.sha256(source).hexdigest(), audio={"music.paq": hashlib.sha256(expected).hexdigest()})
    assert migrate_music_paq(tmp_path)
    assert paq.read_paq(tmp_path / "music.paq") == [
        ("music\\intro.ogg", b"intro"),
        ("music\\game_tunes.txt", b"snd_addGameTune gt1_ingame.ogg\n"),
    ]
    assert not migrate_music_paq(tmp_path)
    assert not (tmp_path / "music.paq.tmp").exists()


@pytest.mark.parametrize("installed", [b"old", b"current", paq.build_entries([("custom", b"original")]), None])
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


def test_bad_audio_response_is_retried_and_custom_music_is_preserved(mocker, tmp_path: Path) -> None:
    music = tmp_path / "music.paq"
    custom = paq.build_entries([("music\\summer\\intro.ogg", b"a"), ("music\\winter\\intro.ogg", b"b")])
    good = paq.build_entries([("music\\intro.ogg", b"music")])
    mocker.patch.dict(assets_fetch.ART_VERSION["audio"], {"music.paq": hashlib.sha256(good).hexdigest()})
    fetch = mocker.patch.object(urllib.request, "urlopen", side_effect=[_FakeResponse(b"bad response"), _FakeResponse(good)])
    console = create_console(tmp_path)
    music.write_bytes(b"earlier broken download")
    [first] = download_missing_paqs(tmp_path, console, names=("music.paq",))
    assert not first.ok
    assert music.read_bytes() == b"earlier broken download"
    [second] = download_missing_paqs(tmp_path, console, names=("music.paq",))
    assert second.ok and music.read_bytes() == good
    [backup] = tmp_path.glob("music.paq.invalid-*")
    assert backup.read_bytes() == b"earlier broken download"
    music.write_bytes(custom)
    assert download_missing_paqs(tmp_path, console, names=("music.paq",)) == ()
    assert not migrate_music_paq(tmp_path)
    assert music.read_bytes() == custom and fetch.call_count == 2


def test_first_boot_rejects_bad_music_and_next_launch_succeeds(mocker, tmp_path: Path) -> None:
    good = paq.build_entries([("music\\intro.ogg", b"music")])
    for name in ("crimson.paq", "sfx.paq"):
        paq.write_paq(tmp_path / name, [("custom", b"preserved")])
    mocker.patch.dict(assets_fetch.ART_VERSION["audio"], {"music.paq": hashlib.sha256(good).hexdigest()})
    fetch = mocker.patch.object(urllib.request, "urlopen", side_effect=[_FakeResponse(b"bad response"), _FakeResponse(good)])
    with pytest.raises(OSError, match=r"music\.paq.*restart to retry"):
        boot_runtime(tmp_path, tmp_path, require_packs=True)
    assert not (tmp_path / "music.paq").exists()
    boot_runtime(tmp_path, tmp_path, require_packs=True)
    assert (tmp_path / "music.paq").read_bytes() == good and fetch.call_count == 2
