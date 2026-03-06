from __future__ import annotations

from pathlib import Path
from typing import cast

import grim.assets as assets_module
from grim.assets import (
    LogoAssets,
    PaqTextureCache,
    PreloadedPaqResources,
    ResourcePaqStore,
    TextureAsset,
    TextureLoader,
)
from grim.raylib_api import rl


def test_paq_texture_cache_reuses_loaded_asset_for_same_rel_path(mocker) -> None:
    cache = PaqTextureCache(entries={"ui/ui_button_64x32.jaz": b"button"}, textures={})
    shared_texture = cast("rl.Texture", object())
    load_texture = mocker.patch.object(
        assets_module,
        "_load_texture_asset_from_bytes",
        return_value=TextureAsset(
            name="ui_buttonSm",
            rel_path="ui/ui_button_64x32.jaz",
            texture=shared_texture,
        ),
    )

    by_name = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz")
    by_path = cache.get_or_load("ui/ui_button_64x32.jaz", "ui/ui_button_64x32.jaz")

    assert by_name is by_path
    assert cache.loaded_count() == 1
    load_texture.assert_called_once_with("ui_buttonSm", "ui/ui_button_64x32.jaz", b"button")


def test_texture_loader_from_assets_root_reuses_preloaded_cache(mocker, tmp_path: Path) -> None:
    shared_cache = PaqTextureCache(entries={}, textures={})
    shared = PreloadedPaqResources(
        assets_root=tmp_path,
        resource_paq=ResourcePaqStore(
            paq_path=tmp_path / "crimson.paq",
            entries={},
            texture_cache=shared_cache,
        ),
        logos=LogoAssets(
            backplasma=TextureAsset("backplasma", "load/backplasma.jaz", None),
            mockup=TextureAsset("mockup", "load/mockup.jaz", None),
            logo_esrb=TextureAsset("logo_esrb", "load/esrb_mature.jaz", None),
            loading=TextureAsset("loading", "load/loading.jaz", None),
            cl_logo=TextureAsset("cl_logo", "load/logo_crimsonland.tga", None),
        ),
    )
    mocker.patch.object(assets_module, "preloaded_paq_resources", return_value=shared)

    loader = TextureLoader.from_assets_root(tmp_path)

    assert loader.assets_root == tmp_path
    assert loader.cache is shared_cache
