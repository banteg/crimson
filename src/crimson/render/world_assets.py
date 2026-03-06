from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData, load_small_font
from grim.raylib_api import rl

from ..sim.world_defs import CREATURE_ASSET

_CREATURE_TEXTURE_IDS: dict[str, TextureId] = {
    "alien": TextureId.ALIEN,
    "lizard": TextureId.LIZARD,
    "spider_sp1": TextureId.SPIDER_SP1,
    "spider_sp2": TextureId.SPIDER_SP2,
    "trooper": TextureId.TROOPER,
    "zombie": TextureId.ZOMBIE,
}


class WorldRenderAssets(msgspec.Struct, frozen=True):
    creature_textures: dict[str, rl.Texture]
    projs: rl.Texture
    particles: rl.Texture
    bullet: rl.Texture
    bullet_trail: rl.Texture
    arrow: rl.Texture
    bonuses: rl.Texture
    bodyset: rl.Texture
    clock_table: rl.Texture
    clock_pointer: rl.Texture
    aim: rl.Texture
    muzzle_flash: rl.Texture
    wicons: rl.Texture
    small_font: SmallFontData


def build_world_render_assets(resources: RuntimeResources) -> WorldRenderAssets:
    creature_textures: dict[str, rl.Texture] = {}
    for asset in sorted(set(CREATURE_ASSET.values())):
        texture_id = _CREATURE_TEXTURE_IDS.get(asset)
        if texture_id is None:
            continue
        creature_textures[asset] = resources.texture(texture_id)

    return WorldRenderAssets(
        creature_textures=creature_textures,
        projs=resources.texture(TextureId.PROJS),
        particles=resources.texture(TextureId.PARTICLES),
        bullet=resources.texture(TextureId.BULLET_I),
        bullet_trail=resources.texture(TextureId.BULLET_TRAIL),
        arrow=resources.texture(TextureId.ARROW),
        bonuses=resources.texture(TextureId.BONUSES),
        bodyset=resources.texture(TextureId.BODYSET),
        clock_table=resources.texture(TextureId.UI_CLOCK_TABLE),
        clock_pointer=resources.texture(TextureId.UI_CLOCK_POINTER),
        aim=resources.texture(TextureId.UI_AIM),
        muzzle_flash=resources.texture(TextureId.MUZZLE_FLASH),
        wicons=resources.texture(TextureId.UI_WICONS),
        small_font=load_small_font(resources.assets_dir),
    )
