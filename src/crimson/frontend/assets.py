from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from grim.assets import PaqTextureCache, TextureLoader, load_paq_entries_from_path

from .types import GameState


@dataclass(slots=True)
class MenuAssets:
    sign: rl.Texture | None
    item: rl.Texture | None
    panel: rl.Texture | None
    labels: rl.Texture | None


def _load_resource_entries(state: GameState) -> dict[str, bytes]:
    return load_paq_entries_from_path(state.resource_paq)


def _ensure_texture_cache(state: GameState) -> PaqTextureCache:
    cache = state.texture_cache
    if cache is None:
        entries = _load_resource_entries(state)
        cache = PaqTextureCache(entries=entries, textures={})
        state.texture_cache = cache
    return cache


def load_menu_assets(state: GameState) -> MenuAssets:
    cache = _ensure_texture_cache(state)
    loader = TextureLoader(assets_root=state.assets_dir, cache=cache)
    return MenuAssets(
        sign=loader.get(name="ui_signCrimson", paq_rel="ui/ui_signCrimson.jaz"),
        item=loader.get(name="ui_menuItem", paq_rel="ui/ui_menuItem.jaz"),
        panel=loader.get(name="ui_menuPanel", paq_rel="ui/ui_menuPanel.jaz"),
        labels=loader.get(name="ui_itemTexts", paq_rel="ui/ui_itemTexts.jaz"),
    )
