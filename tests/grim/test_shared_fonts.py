from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import grim.fonts.grim_mono as grim_mono_module
import grim.fonts.small as small_module
from grim.assets import LogoAssets, PaqTextureCache, PreloadedPaqResources, ResourcePaqStore, TextureAsset
from grim.raylib_api import rl


def _empty_logos() -> LogoAssets:
    return LogoAssets(
        backplasma=TextureAsset("backplasma", "load/backplasma.jaz", None),
        mockup=TextureAsset("mockup", "load/mockup.jaz", None),
        logo_esrb=TextureAsset("logo_esrb", "load/esrb_mature.jaz", None),
        loading=TextureAsset("loading", "load/loading.jaz", None),
        cl_logo=TextureAsset("cl_logo", "load/logo_crimsonland.tga", None),
    )


def test_small_font_uses_shared_preload_and_skips_unload(mocker, tmp_path: Path) -> None:
    texture = cast("rl.Texture", object())
    cache = PaqTextureCache(
        entries={"load/smallFnt.dat": bytes(range(16)), "load/smallWhite.tga": b"atlas"},
        textures={"smallWhite": TextureAsset("smallWhite", "load/smallWhite.tga", texture)},
    )
    shared = PreloadedPaqResources(
        assets_root=tmp_path,
        resource_paq=ResourcePaqStore(
            paq_path=tmp_path / "crimson.paq",
            entries=cache.entries,
            texture_cache=cache,
        ),
        logos=_empty_logos(),
    )
    mocker.patch.object(small_module, "preloaded_paq_resources", return_value=shared)
    mocker.patch.object(small_module.rl, "set_texture_filter")
    unload_texture = mocker.patch.object(small_module.rl, "unload_texture")

    small_module.clear_preloaded_small_font(tmp_path)
    font = small_module.preload_small_font(tmp_path)
    small_module.unload_small_font(font)
    small_module.clear_preloaded_small_font(tmp_path)

    assert font.shared is True
    assert font.texture is texture
    unload_texture.assert_not_called()


def test_grim_mono_font_uses_shared_preload_and_skips_unload(mocker, tmp_path: Path) -> None:
    texture = cast("rl.Texture", SimpleNamespace(width=256.0, height=256.0))
    cache = PaqTextureCache(
        entries={"load/default_font_courier.tga": b"atlas"},
        textures={
            "default_font_courier": TextureAsset(
                "default_font_courier",
                "load/default_font_courier.tga",
                texture,
            ),
        },
    )
    shared = PreloadedPaqResources(
        assets_root=tmp_path,
        resource_paq=ResourcePaqStore(
            paq_path=tmp_path / "crimson.paq",
            entries=cache.entries,
            texture_cache=cache,
        ),
        logos=_empty_logos(),
    )
    mocker.patch.object(grim_mono_module, "preloaded_paq_resources", return_value=shared)
    mocker.patch.object(grim_mono_module.rl, "set_texture_filter")
    unload_texture = mocker.patch.object(grim_mono_module.rl, "unload_texture")

    grim_mono_module.clear_preloaded_grim_mono_font(tmp_path)
    font = grim_mono_module.preload_grim_mono_font(tmp_path)
    grim_mono_module.unload_grim_mono_font(font)
    grim_mono_module.clear_preloaded_grim_mono_font(tmp_path)

    assert font.shared is True
    assert font.texture is texture
    unload_texture.assert_not_called()
