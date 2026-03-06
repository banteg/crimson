from __future__ import annotations

import msgspec

from grim.assets import TextureId, runtime_texture_view_for
from grim.raylib_api import rl

from ..game.types import GameState


class MenuAssets(msgspec.Struct):
    sign: rl.Texture
    item: rl.Texture
    panel: rl.Texture
    labels: rl.Texture


def _ensure_texture_cache(state: GameState):
    if state.resources is None:
        raise RuntimeError("runtime resources are not loaded")
    return runtime_texture_view_for(state.assets_dir)


def _require_menu_texture(texture: rl.Texture | None, *, rel_path: str) -> rl.Texture:
    if texture is None:
        raise FileNotFoundError(f"Missing menu asset texture: {rel_path}")
    return texture


def load_menu_assets(state: GameState) -> MenuAssets:
    if state.resources is None:
        raise RuntimeError("runtime resources are not loaded")
    return MenuAssets(
        sign=_require_menu_texture(
            state.resources.texture(TextureId.UI_SIGN_CRIMSON),
            rel_path="ui/ui_signCrimson.jaz",
        ),
        item=_require_menu_texture(
            state.resources.texture(TextureId.UI_MENU_ITEM),
            rel_path="ui/ui_menuItem.jaz",
        ),
        panel=_require_menu_texture(
            state.resources.texture(TextureId.UI_MENU_PANEL),
            rel_path="ui/ui_menuPanel.jaz",
        ),
        labels=_require_menu_texture(
            state.resources.texture(TextureId.UI_ITEM_TEXTS),
            rel_path="ui/ui_itemTexts.jaz",
        ),
    )
