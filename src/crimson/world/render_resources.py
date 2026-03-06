from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

import msgspec

from grim.assets import TextureId, texture_for
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer

from ..creatures.anim import creature_corpse_frame_for_type
from ..creatures.runtime import CreaturePool
from ..effects import FxQueue, FxQueueRotated
from ..gameplay import GameplayState
from ..render.frame import RenderFrame
from ..render.rtx.mode import RtxRenderMode
from ..render.terrain_fx import FxQueueTextures, bake_fx_queues
from ..sim.state_types import PlayerState
from ..sim.world_defs import CREATURE_ASSET

_CREATURE_TEXTURE_IDS: dict[str, TextureId] = {
    "alien": TextureId.ALIEN,
    "lizard": TextureId.LIZARD,
    "spider_sp1": TextureId.SPIDER_SP1,
    "spider_sp2": TextureId.SPIDER_SP2,
    "trooper": TextureId.TROOPER,
    "zombie": TextureId.ZOMBIE,
}


class RenderResources(msgspec.Struct):
    assets_dir: Path
    world_size: float = 1024.0
    config: CrimsonConfig | None = None

    ground: GroundRenderer | None = None
    fx_queue: FxQueue = msgspec.field(default_factory=FxQueue)
    fx_queue_rotated: FxQueueRotated = msgspec.field(default_factory=FxQueueRotated)
    fx_textures: FxQueueTextures | None = None
    creature_textures: dict[str, rl.Texture] = msgspec.field(default_factory=dict)
    projs_texture: rl.Texture | None = None
    particles_texture: rl.Texture | None = None
    bullet_texture: rl.Texture | None = None
    bullet_trail_texture: rl.Texture | None = None
    arrow_texture: rl.Texture | None = None
    bonuses_texture: rl.Texture | None = None
    bodyset_texture: rl.Texture | None = None
    clock_table_texture: rl.Texture | None = None
    clock_pointer_texture: rl.Texture | None = None
    aim_texture: rl.Texture | None = None
    muzzle_flash_texture: rl.Texture | None = None
    wicons_texture: rl.Texture | None = None

    def load_texture(self, texture_id: TextureId) -> rl.Texture | None:
        return texture_for(self.assets_dir, texture_id)

    def sync_ground_settings(self) -> None:
        if self.ground is None:
            return
        if self.config is None:
            self.ground.texture_scale = 1.0
            self.ground.screen_width = None
            self.ground.screen_height = None
            return
        self.ground.texture_scale = self.config.texture_scale
        self.ground.screen_width = float(self.config.screen_width)
        self.ground.screen_height = float(self.config.screen_height)

    def set_ground_textures(
        self,
        *,
        base: rl.Texture,
        overlay: rl.Texture,
        detail: rl.Texture,
    ) -> None:
        if self.ground is None:
            self.ground = GroundRenderer(
                texture=base,
                overlay=overlay,
                overlay_detail=detail,
                width=int(self.world_size),
                height=int(self.world_size),
                texture_scale=1.0,
                screen_width=None,
                screen_height=None,
            )
        else:
            self.ground.texture = base
            self.ground.overlay = overlay
            self.ground.overlay_detail = detail
        self.sync_ground_settings()

    def schedule_ground_generation(self, *, seed: int, layers: int = 3) -> None:
        if self.ground is None:
            return
        self.ground.schedule_generate(seed=int(seed), layers=int(layers))

    def process_ground_pending(self) -> None:
        if self.ground is None:
            return
        self.sync_ground_settings()
        self.ground.process_pending()

    def open(self, *, terrain_seed: int) -> None:
        self.close()
        self.creature_textures.clear()

        base = cast(rl.Texture, self.load_texture(TextureId.TER_Q1_BASE))
        overlay = cast(rl.Texture, self.load_texture(TextureId.TER_Q1_OVERLAY))
        self.set_ground_textures(base=base, overlay=overlay, detail=overlay)
        self.schedule_ground_generation(seed=int(terrain_seed), layers=3)

        for asset in sorted(set(CREATURE_ASSET.values())):
            texture_id = _CREATURE_TEXTURE_IDS.get(asset)
            if texture_id is None:
                continue
            texture = self.load_texture(texture_id)
            if texture is not None:
                self.creature_textures[asset] = texture

        self.projs_texture = self.load_texture(TextureId.PROJS)
        self.particles_texture = self.load_texture(TextureId.PARTICLES)
        self.bullet_texture = self.load_texture(TextureId.BULLET_I)
        self.bullet_trail_texture = self.load_texture(TextureId.BULLET_TRAIL)
        self.arrow_texture = self.load_texture(TextureId.ARROW)
        self.bonuses_texture = self.load_texture(TextureId.BONUSES)
        self.wicons_texture = self.load_texture(TextureId.UI_WICONS)
        self.bodyset_texture = self.load_texture(TextureId.BODYSET)
        self.clock_table_texture = self.load_texture(TextureId.UI_CLOCK_TABLE)
        self.clock_pointer_texture = self.load_texture(TextureId.UI_CLOCK_POINTER)
        self.aim_texture = self.load_texture(TextureId.UI_AIM)
        self.muzzle_flash_texture = self.load_texture(TextureId.MUZZLE_FLASH)

        if self.particles_texture is not None and self.bodyset_texture is not None:
            self.fx_textures = FxQueueTextures(
                particles=self.particles_texture,
                bodyset=self.bodyset_texture,
            )
        else:
            self.fx_textures = None

    def close(self) -> None:
        if self.ground is not None and self.ground.render_target is not None:
            rl.unload_render_texture(self.ground.render_target)
            self.ground.render_target = None
        self.ground = None

        self.creature_textures.clear()
        self.projs_texture = None
        self.particles_texture = None
        self.bullet_texture = None
        self.bullet_trail_texture = None
        self.arrow_texture = None
        self.bonuses_texture = None
        self.wicons_texture = None
        self.bodyset_texture = None
        self.clock_table_texture = None
        self.clock_pointer_texture = None
        self.aim_texture = None
        self.muzzle_flash_texture = None
        self.fx_textures = None
        self.fx_queue.clear()
        self.fx_queue_rotated.clear()

    def bake_fx_queues(
        self,
        *,
        corpse_frame_for_type: Callable[[int], int] = creature_corpse_frame_for_type,
    ) -> None:
        if self.ground is None or self.fx_textures is None:
            return
        if not (self.fx_queue.count or self.fx_queue_rotated.count):
            return
        bake_fx_queues(
            self.ground,
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            textures=self.fx_textures,
            corpse_frame_for_type=corpse_frame_for_type,
        )

    def build_render_frame(
        self,
        *,
        state: GameplayState,
        players: list[PlayerState],
        creatures: CreaturePool,
        camera: Vec2,
        demo_mode_active: bool,
        elapsed_ms: float,
        bonus_anim_phase: float,
        lan_player_rings_enabled: bool,
        lan_local_aim_indicators_only: bool,
        lan_local_player_slot_index: int,
        rtx_mode: RtxRenderMode,
    ) -> RenderFrame:
        return RenderFrame(
            assets_dir=self.assets_dir,
            world_size=float(self.world_size),
            demo_mode_active=bool(demo_mode_active),
            config=self.config,
            camera=camera,
            ground=self.ground,
            state=state,
            players=players,
            creatures=creatures,
            creature_textures=self.creature_textures,
            projs_texture=self.projs_texture,
            particles_texture=self.particles_texture,
            bullet_texture=self.bullet_texture,
            bullet_trail_texture=self.bullet_trail_texture,
            arrow_texture=self.arrow_texture,
            bonuses_texture=self.bonuses_texture,
            bodyset_texture=self.bodyset_texture,
            clock_table_texture=self.clock_table_texture,
            clock_pointer_texture=self.clock_pointer_texture,
            aim_texture=self.aim_texture,
            muzzle_flash_texture=self.muzzle_flash_texture,
            wicons_texture=self.wicons_texture,
            elapsed_ms=float(elapsed_ms),
            bonus_anim_phase=float(bonus_anim_phase),
            lan_player_rings_enabled=bool(lan_player_rings_enabled),
            lan_local_aim_indicators_only=bool(lan_local_aim_indicators_only),
            lan_local_player_slot_index=int(lan_local_player_slot_index),
            rtx_mode=rtx_mode,
        )
