from __future__ import annotations

import msgspec

from grim.assets import PaqTextureCache, TextureLoader, load_paq_entries_from_path
from grim.raylib_api import rl

from .types import FrontendContext


class MenuAssets(msgspec.Struct):
    sign: rl.Texture
    item: rl.Texture
    panel: rl.Texture
    labels: rl.Texture


def _load_resource_entries(state: FrontendContext) -> dict[str, bytes]:
    return load_paq_entries_from_path(state.resource_paq)


def _ensure_texture_cache(state: FrontendContext) -> PaqTextureCache:
    cache = state.texture_cache
    if cache is None:
        entries = _load_resource_entries(state)
        cache = PaqTextureCache(entries=entries, textures={})
        state.texture_cache = cache
    return cache


def _require_menu_texture(texture: rl.Texture | None, *, rel_path: str) -> rl.Texture:
    if texture is None:
        raise FileNotFoundError(f"Missing menu asset texture: {rel_path}")
    return texture


def load_menu_assets(state: FrontendContext) -> MenuAssets:
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
