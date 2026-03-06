from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.raylib_api import rl

from ..game.types import GameState


class MenuAssets(msgspec.Struct):
    sign: rl.Texture
    item: rl.Texture
    panel: rl.Texture
    labels: rl.Texture


def require_runtime_resources(state: GameState) -> RuntimeResources:
    if state.resources is None:
        raise RuntimeError("runtime resources are not loaded")
    return state.resources


def _ensure_texture_cache(state: GameState) -> RuntimeResources:
    return require_runtime_resources(state)


def load_menu_assets(state: GameState) -> MenuAssets:
    resources = require_runtime_resources(state)
    return MenuAssets(
        sign=resources.texture(TextureId.UI_SIGN_CRIMSON),
        item=resources.texture(TextureId.UI_MENU_ITEM),
        panel=resources.texture(TextureId.UI_MENU_PANEL),
        labels=resources.texture(TextureId.UI_ITEM_TEXTS),
    )
