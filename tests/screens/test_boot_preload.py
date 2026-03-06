from __future__ import annotations

from typing import cast

import crimson.screens.boot as boot_module
from crimson.screens.boot import BootView
from grim.assets import LogoAssets, PaqTextureCache, PreloadedPaqResources, ResourcePaqStore, TextureAsset
from grim.raylib_api import rl


def test_boot_open_adopts_preloaded_resource_cache(make_game_state, mocker) -> None:
    state = make_game_state()
    view = BootView(state)
    texture = cast("rl.Texture", object())
    shared_cache = PaqTextureCache(
        entries={},
        textures={
            "backplasma": TextureAsset("backplasma", "load/backplasma.jaz", texture),
            "mockup": TextureAsset("mockup", "load/mockup.jaz", texture),
            "logo_esrb": TextureAsset("logo_esrb", "load/esrb_mature.jaz", texture),
            "loading": TextureAsset("loading", "load/loading.jaz", texture),
            "cl_logo": TextureAsset("cl_logo", "load/logo_crimsonland.tga", texture),
        },
    )
    logos = LogoAssets(
        backplasma=shared_cache.textures["backplasma"],
        mockup=shared_cache.textures["mockup"],
        logo_esrb=shared_cache.textures["logo_esrb"],
        loading=shared_cache.textures["loading"],
        cl_logo=shared_cache.textures["cl_logo"],
    )
    resources = PreloadedPaqResources(
        assets_root=state.assets_dir,
        logos=logos,
        resource_paq=ResourcePaqStore(
            paq_path=state.resource_paq,
            entries={},
            texture_cache=shared_cache,
        ),
    )
    preload = mocker.patch.object(boot_module, "preload_paq_resources", return_value=resources)
    init_audio = mocker.patch.object(boot_module, "init_audio_state", return_value=object())
    exec_line = mocker.patch.object(type(state.console), "exec_line")

    view.open()

    preload.assert_called_once_with(state.assets_dir, paq_path=state.resource_paq)
    init_audio.assert_called_once_with(state.config, state.assets_dir, state.console)
    exec_line.assert_called_once_with("exec music/game_tunes.txt")
    assert state.logos is logos
    assert state.texture_cache is shared_cache
