from __future__ import annotations

import msgspec

from grim.assets import PaqTextureCache, TextureLoader, load_paq_entries_from_path, preloaded_paq_resources
from grim.raylib_api import rl

from ..game.types import GameState
from ..ui.perk_menu import UiButtonTextureSet


class MenuAssets(msgspec.Struct):
    sign: rl.Texture
    item: rl.Texture
    panel: rl.Texture
    labels: rl.Texture


class ClassicUiAssets(msgspec.Struct):
    button_sm: rl.Texture | None
    button_md: rl.Texture | None
    button_textures: UiButtonTextureSet
    check_on: rl.Texture | None
    check_off: rl.Texture | None
    rect_on: rl.Texture | None
    rect_off: rl.Texture | None
    drop_on: rl.Texture | None
    drop_off: rl.Texture | None
    arrow: rl.Texture | None


def _load_resource_entries(state: GameState) -> dict[str, bytes]:
    shared = preloaded_paq_resources(state.assets_dir)
    if shared is not None:
        return shared.resource_paq.entries
    return load_paq_entries_from_path(state.resource_paq)


def _ensure_texture_cache(state: GameState) -> PaqTextureCache:
    cache = state.texture_cache
    if cache is None:
        shared = preloaded_paq_resources(state.assets_dir)
        if shared is not None:
            cache = shared.resource_paq.texture_cache
        else:
            entries = _load_resource_entries(state)
            cache = PaqTextureCache(entries=entries, textures={})
        state.texture_cache = cache
    return cache


def _require_menu_texture(texture: rl.Texture | None, *, rel_path: str) -> rl.Texture:
    if texture is None:
        raise FileNotFoundError(f"Missing menu asset texture: {rel_path}")
    return texture


def load_menu_assets(state: GameState) -> MenuAssets:
    cache = _ensure_texture_cache(state)
    loader = TextureLoader(assets_root=state.assets_dir, cache=cache)
    return MenuAssets(
        sign=_require_menu_texture(
            loader.get(name="ui_signCrimson", paq_rel="ui/ui_signCrimson.jaz"),
            rel_path="ui/ui_signCrimson.jaz",
        ),
        item=_require_menu_texture(
            loader.get(name="ui_menuItem", paq_rel="ui/ui_menuItem.jaz"),
            rel_path="ui/ui_menuItem.jaz",
        ),
        panel=_require_menu_texture(
            loader.get(name="ui_menuPanel", paq_rel="ui/ui_menuPanel.jaz"),
            rel_path="ui/ui_menuPanel.jaz",
        ),
        labels=_require_menu_texture(
            loader.get(name="ui_itemTexts", paq_rel="ui/ui_itemTexts.jaz"),
            rel_path="ui/ui_itemTexts.jaz",
        ),
    )


def load_classic_ui_assets(state: GameState, *, cache: PaqTextureCache | None = None) -> ClassicUiAssets:
    if cache is None:
        cache = _ensure_texture_cache(state)
    button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
    button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
    return ClassicUiAssets(
        button_sm=button_sm,
        button_md=button_md,
        button_textures=UiButtonTextureSet(button_sm=button_sm, button_md=button_md),
        check_on=cache.get_or_load("ui_checkOn", "ui/ui_checkOn.jaz").texture,
        check_off=cache.get_or_load("ui_checkOff", "ui/ui_checkOff.jaz").texture,
        rect_on=cache.get_or_load("ui_rectOn", "ui/ui_rectOn.jaz").texture,
        rect_off=cache.get_or_load("ui_rectOff", "ui/ui_rectOff.jaz").texture,
        drop_on=cache.get_or_load("ui_dropOn", "ui/ui_dropDownOn.jaz").texture,
        drop_off=cache.get_or_load("ui_dropOff", "ui/ui_dropDownOff.jaz").texture,
        arrow=cache.get_or_load("ui_arrow", "ui/ui_arrow.jaz").texture,
    )
