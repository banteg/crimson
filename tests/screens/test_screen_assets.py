from __future__ import annotations

from typing import cast

from crimson.screens.assets import load_classic_ui_assets
from grim.assets import PaqTextureCache, TextureAsset
from grim.raylib_api import rl


def test_load_classic_ui_assets_reuses_cached_widget_textures(make_game_state) -> None:
    state = make_game_state()
    textures = {
        "ui_buttonSm": TextureAsset("ui_buttonSm", "ui/ui_button_64x32.jaz", cast("rl.Texture", object())),
        "ui_buttonMd": TextureAsset("ui_buttonMd", "ui/ui_button_128x32.jaz", cast("rl.Texture", object())),
        "ui_checkOn": TextureAsset("ui_checkOn", "ui/ui_checkOn.jaz", cast("rl.Texture", object())),
        "ui_checkOff": TextureAsset("ui_checkOff", "ui/ui_checkOff.jaz", cast("rl.Texture", object())),
        "ui_rectOn": TextureAsset("ui_rectOn", "ui/ui_rectOn.jaz", cast("rl.Texture", object())),
        "ui_rectOff": TextureAsset("ui_rectOff", "ui/ui_rectOff.jaz", cast("rl.Texture", object())),
        "ui_dropOn": TextureAsset("ui_dropOn", "ui/ui_dropDownOn.jaz", cast("rl.Texture", object())),
        "ui_dropOff": TextureAsset("ui_dropOff", "ui/ui_dropDownOff.jaz", cast("rl.Texture", object())),
        "ui_arrow": TextureAsset("ui_arrow", "ui/ui_arrow.jaz", cast("rl.Texture", object())),
    }
    state.texture_cache = PaqTextureCache(entries={}, textures=textures)

    assets = load_classic_ui_assets(state)

    assert assets.button_sm is textures["ui_buttonSm"].texture
    assert assets.button_md is textures["ui_buttonMd"].texture
    assert assets.check_on is textures["ui_checkOn"].texture
    assert assets.check_off is textures["ui_checkOff"].texture
    assert assets.rect_on is textures["ui_rectOn"].texture
    assert assets.rect_off is textures["ui_rectOff"].texture
    assert assets.drop_on is textures["ui_dropOn"].texture
    assert assets.drop_off is textures["ui_dropOff"].texture
    assert assets.arrow is textures["ui_arrow"].texture
    assert assets.button_textures.button_sm is assets.button_sm
    assert assets.button_textures.button_md is assets.button_md
