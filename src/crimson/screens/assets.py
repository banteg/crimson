from __future__ import annotations

import msgspec

from grim.assets import TEXTURE_SPECS, RuntimeResources, TextureId
from grim.raylib_api import rl

from ..game.types import GameState


class MenuAssets(msgspec.Struct):
    sign: rl.Texture
    item: rl.Texture
    panel: rl.Texture
    labels: rl.Texture


def _ensure_texture_cache(state: GameState) -> RuntimeResources:
    if state.resources is None:
        raise RuntimeError("runtime resources are not loaded")
    return state.resources


def _require_runtime_texture(resources: RuntimeResources, texture_id: TextureId) -> rl.Texture:
    texture = resources.texture(texture_id)
    rel_path = TEXTURE_SPECS[texture_id].rel_path
    if texture is None:
        raise FileNotFoundError(f"Missing menu asset texture: {rel_path}")
    return texture


def load_menu_assets(state: GameState) -> MenuAssets:
    resources = _ensure_texture_cache(state)
    return MenuAssets(
        sign=_require_runtime_texture(resources, TextureId.UI_SIGN_CRIMSON),
        item=_require_runtime_texture(resources, TextureId.UI_MENU_ITEM),
        panel=_require_runtime_texture(resources, TextureId.UI_MENU_PANEL),
        labels=_require_runtime_texture(resources, TextureId.UI_ITEM_TEXTS),
    )
