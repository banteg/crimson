from __future__ import annotations

from collections import Counter
from pathlib import Path
from unittest.mock import Mock

import pytest

from grim import audio, music, paq, sfx
from grim.config import default_crimson_cfg
from grim.console import ConsoleLog, ConsoleState
from grim.raylib_api import rl
from grim.sfx_map import SFX_SPECS, SfxId


@pytest.fixture
def audio_assets(tmp_path):
    names = sorted({spec.entry_name for spec in SFX_SPECS.values()})
    paq.write_paq(tmp_path / sfx.SFX_PAK_NAME, [(name, b"stub PCM") for name in names])
    paq.write_paq(
        tmp_path / music.MUSIC_PAK_NAME,
        [(paths[0], b"stub Vorbis") for paths in music.MUSIC_TRACKS.values()],
    )
    return tmp_path, ConsoleState(base_dir=tmp_path, log=ConsoleLog(base_dir=tmp_path))


@pytest.fixture
def audio_backend(mocker):
    created: list[tuple[str, object]] = []
    released = mocker.Mock()

    def allocate(kind: str):
        handle = object()
        created.append((kind, handle))
        return handle

    for kind, load, unload in (
        ("wave", "load_wave_from_memory", "unload_wave"),
        ("source", "load_sound_from_wave", "unload_sound"),
        ("alias", "load_sound_alias", "unload_sound_alias"),
        ("music", "load_music_stream_from_memory", "unload_music_stream"),
    ):
        mocker.patch.object(rl, load, side_effect=lambda *_, kind=kind: allocate(kind))
        released.attach_mock(mocker.patch.object(rl, unload), kind)
    for name in ("is_wave_valid", "is_sound_valid", "is_music_valid"):
        mocker.patch.object(rl, name, return_value=True)
    mocker.patch.object(rl, "is_audio_device_ready", side_effect=[False, True])
    mocker.patch.object(rl, "init_audio_device")
    close = mocker.patch.object(rl, "close_audio_device")
    mocker.patch.object(rl, "set_music_volume")
    mocker.patch.object(rl, "set_sound_volume")
    return created, released, close


def _releases(calls: Mock) -> list[tuple[str, object]]:
    return [(call[0], call.args[0]) for call in calls.mock_calls]


def test_invalid_optional_music_uses_real_decoder_and_does_not_consume_an_id(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.ogg"
    path.write_bytes(b"OggS")
    console = ConsoleState(base_dir=tmp_path, log=ConsoleLog(base_dir=tmp_path))
    state = music.init_music_state(ready=True, enabled=True, volume=0.5)
    assert music.load_music_track(state, tmp_path, path.name, console=console) is None
    assert state.tracks == {} and state.queue == []
    assert state.next_track_id == 0
    assert console.log.lines == ["SFX Tune 0 <- 'corrupt.ogg' FAILED"]


def test_invalid_wave_uses_real_decoder_and_fails_before_voice_creation(mocker) -> None:
    load_sound = mocker.patch.object(rl, "load_sound_from_wave")
    state = sfx.init_sfx_state(ready=True, enabled=True, volume=1.0)
    with pytest.raises(ValueError, match="failed to decode sfx"):
        sfx._load_sample_from_data(state, entry_name="corrupt.wav", data=b"RIFF")
    load_sound.assert_not_called()


@pytest.mark.parametrize("failure", ["wave", "source", "alias", "music", "volume", "exception"])
def test_failed_initialization_releases_every_acquired_resource(audio_assets, audio_backend, mocker, failure) -> None:
    root, console = audio_assets
    created, released, close = audio_backend
    if failure == "wave":
        mocker.patch.object(rl, "is_wave_valid", return_value=False)
    elif failure == "source":
        mocker.patch.object(rl, "is_sound_valid", return_value=False)
    elif failure == "alias":
        mocker.patch.object(rl, "is_sound_valid", side_effect=[True, True, False])
    elif failure == "music":
        mocker.patch.object(rl, "is_music_valid", side_effect=[True, True, False])
    elif failure == "volume":
        mocker.patch.object(rl, "set_music_volume", side_effect=RuntimeError("volume setup failed"))
    else:
        mocker.patch.object(rl, "load_sound_from_wave", side_effect=RuntimeError("sound allocation failed"))
    with pytest.raises((ValueError, RuntimeError)):
        audio.init_audio_state(default_crimson_cfg(), root, console)
    assert Counter(created) == Counter(_releases(released))
    close.assert_called_once_with()


def test_missing_music_entry_is_preflighted_and_loaded_sfx_are_released(audio_assets, audio_backend, mocker) -> None:
    root, console = audio_assets
    created, released, close = audio_backend
    paq.write_paq(root / music.MUSIC_PAK_NAME, [("music/intro.ogg", b"stub Vorbis")])
    load_music = mocker.spy(rl, "load_music_stream_from_memory")
    with pytest.raises(FileNotFoundError, match="shortie_monk"):
        audio.init_audio_state(default_crimson_cfg(), root, console)
    load_music.assert_not_called()
    assert any(kind == "source" for kind, _ in created)
    assert Counter(created) == Counter(_releases(released))
    close.assert_called_once_with()


@pytest.mark.parametrize("borrowed_device", [False, True])
def test_shutdown_releases_aliases_before_sources_and_only_owns_its_device(
    audio_assets,
    audio_backend,
    mocker,
    borrowed_device,
) -> None:
    root, console = audio_assets
    created, released, close = audio_backend
    mocker.patch.object(rl, "is_audio_device_ready", side_effect=[borrowed_device, True])
    state = audio.init_audio_state(default_crimson_cfg(), root, console)
    owned = list(state.sfx.owned_samples)
    assert state.sfx.samples[SfxId.SHOCK_FIRE] is state.sfx.samples[SfxId.SHOCK_FIRE_ALT]
    audio.shutdown_audio(state)
    audio.shutdown_audio(state)
    release_order = _releases(released)
    assert Counter(created) == Counter(release_order)
    for sample in owned:
        for alias in sample.aliases:
            assert release_order.index(("alias", alias.sound)) < release_order.index(("source", sample.source.sound))
    assert close.call_count == (0 if borrowed_device else 1)
    assert not state.ready and not state.sfx.ready and not state.music.ready


def test_failed_reload_keeps_existing_samples_and_successful_retry_replaces_them(audio_assets, audio_backend, mocker):
    root, console = audio_assets
    created, released, _ = audio_backend
    state = sfx.init_sfx_state(ready=True, enabled=True, volume=1.0)
    sfx.load_sfx_index(state, root, console)
    original = dict(state.samples)
    validity = mocker.patch.object(rl, "is_sound_valid", return_value=False)
    with pytest.raises(ValueError, match="failed to load sfx"):
        sfx.load_sfx_index(state, root, console)
    assert state.samples == original
    validity.return_value = True
    sfx.load_sfx_index(state, root, console)
    assert state.samples != original
    sfx.shutdown_sfx(state)
    assert Counter(created) == Counter(_releases(released))


def test_memory_stream_keeps_its_bytes_through_shutdown(mocker) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=1.0)
    track = music.MusicTrack(stream=rl.Music(), track_id=0, source_data=b"borrowed Vorbis data")
    state.tracks["memory"] = track

    def unload(_stream):
        assert track.source_data == b"borrowed Vorbis data"

    mocker.patch.object(rl, "unload_music_stream", side_effect=unload)
    music.shutdown_music(state)
    assert track.source_data is None
