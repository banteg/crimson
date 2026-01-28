from __future__ import annotations

from typing import TYPE_CHECKING

from grim.assets import PaqTextureCache, load_paq_entries_from_path

if TYPE_CHECKING:
    from ..game import GameState


def _load_resource_entries(state: GameState) -> dict[str, bytes]:
    return load_paq_entries_from_path(state.resource_paq)


def _ensure_texture_cache(state: GameState) -> PaqTextureCache:
    cache = state.texture_cache
    if cache is None:
        entries = _load_resource_entries(state)
        cache = PaqTextureCache(entries=entries, textures={})
        state.texture_cache = cache
    return cache
