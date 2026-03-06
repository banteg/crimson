from __future__ import annotations

from types import SimpleNamespace

import crimson.screens.boot as boot_module
from crimson.screens.boot import BootView


def test_boot_open_eagerly_loads_runtime_resources_and_audio(make_game_state, mocker) -> None:
    state = make_game_state()
    resources = SimpleNamespace(
        textures={"dummy": object()},
    )
    audio = object()

    load_runtime_resources = mocker.patch.object(boot_module, "load_runtime_resources", return_value=resources)
    init_audio_state = mocker.patch.object(boot_module, "init_audio_state", return_value=audio)

    view = BootView(state)
    view.open()

    load_runtime_resources.assert_called_once_with(state.assets_dir)
    init_audio_state.assert_called_once_with(state.config, state.assets_dir, state.console)
    assert state.resources is resources
    assert state.audio is audio


def test_boot_close_unloads_runtime_resources_and_audio(make_game_state, mocker) -> None:
    resources = object()
    audio = object()
    state = make_game_state(resources=resources, audio=audio)
    shutdown_audio = mocker.patch.object(boot_module, "shutdown_audio")
    unload_runtime_resources = mocker.patch.object(boot_module, "unload_runtime_resources")

    view = BootView(state)
    view.close()

    shutdown_audio.assert_called_once_with(audio)
    unload_runtime_resources.assert_called_once_with(resources)
    assert state.audio is None
    assert state.resources is None
