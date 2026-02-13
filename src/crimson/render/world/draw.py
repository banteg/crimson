from __future__ import annotations

from dataclasses import dataclass
import math
from typing import TYPE_CHECKING, Any

import pyray as rl

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp
from grim.terrain_render import _maybe_alpha_test

from ...creatures.spawn import CreatureFlags, CreatureTypeId
from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId, SIZE_CODE_GRID
from ...perks import PerkId
from ...perks.helpers import perk_active
from ...sim.world_defs import CREATURE_ANIM, CREATURE_ASSET
from ..frame import RenderFrame
from .constants import _RAD_TO_DEG, monster_vision_fade_alpha
from .mixin_base import WorldRendererMixinBase

if TYPE_CHECKING:
    from ...sim.state_types import PlayerState


@dataclass(frozen=True, slots=True)
class _WorldDrawContext:
    camera: Vec2
    view_scale: Vec2
    scale: float
    entity_alpha: float
    trooper_texture: rl.Texture | None
    particles_texture: rl.Texture | None
    monster_vision: bool
    monster_vision_src: rl.Rectangle | None
    poison_src: rl.Rectangle | None


class WorldRendererDrawMixin(WorldRendererMixinBase):
    def draw(
        self,
        *,
        render_frame: RenderFrame | None = None,
        draw_aim_indicators: bool = True,
        entity_alpha: float = 1.0,
    ) -> None:
        self._render_frame = render_frame if render_frame is not None else self._world.build_render_frame()
        try:
            self._draw_with_active_frame(draw_aim_indicators=draw_aim_indicators, entity_alpha=entity_alpha)
        finally:
            self._render_frame = None

    def _draw_with_active_frame(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        entity_alpha = clamp(float(entity_alpha), 0.0, 1.0)
        camera, view_scale, scale, screen_size = self._compute_view_transform()
        self._draw_background(camera=camera, screen_size=screen_size, view_scale=view_scale)
        if entity_alpha <= 1e-3:
            return

        with _maybe_alpha_test(bool(self._alpha_test_enabled())):
            ctx = self._build_draw_context(
                camera=camera,
                view_scale=view_scale,
                scale=scale,
                entity_alpha=entity_alpha,
            )
            self._draw_players(ctx=ctx, alive=False)
            self._draw_creatures(ctx=ctx)
            self._draw_freeze_overlay(ctx=ctx)
            self._draw_players(ctx=ctx, alive=True)
            self._draw_projectiles_and_effects(ctx=ctx)
            self._draw_bonus_and_ui(ctx=ctx, draw_aim_indicators=draw_aim_indicators)

    def _compute_view_transform(self) -> tuple[Vec2, Vec2, float, Vec2]:
        screen_size = self._camera_screen_size()
        camera = self._clamp_camera(self.camera, screen_size)
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        scale_x = out_w / screen_size.x if screen_size.x > 0 else 1.0
        scale_y = out_h / screen_size.y if screen_size.y > 0 else 1.0
        view_scale = Vec2(scale_x, scale_y)
        scale = self._view_scale_avg(view_scale)
        return camera, view_scale, scale, screen_size

    def _draw_background(self, *, camera: Vec2, screen_size: Vec2, view_scale: Vec2) -> None:
        clear_color = rl.Color(10, 10, 12, 255)
        ground = self.ground
        rl.clear_background(clear_color)
        if ground is not None:
            ground.draw(camera, screen_w=screen_size.x, screen_h=screen_size.y)
            return

        # World bounds for debug if terrain is missing.
        world_min = camera.mul_components(view_scale)
        world_max = (camera + Vec2(float(self.world_size), float(self.world_size))).mul_components(view_scale)
        rl.draw_rectangle_lines(
            int(world_min.x),
            int(world_min.y),
            int(world_max.x - world_min.x),
            int(world_max.y - world_min.y),
            rl.Color(40, 40, 55, 255),
        )

    def _alpha_test_enabled(self) -> bool:
        ground = self.ground
        if ground is None:
            return True
        return bool(getattr(ground, "alpha_test", True))

    @staticmethod
    def _effect_src_rect(texture: rl.Texture, effect_id: EffectId) -> rl.Rectangle | None:
        atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(effect_id))
        if atlas is None:
            return None
        grid = SIZE_CODE_GRID.get(int(atlas.size_code))
        if not grid:
            return None
        frame = int(atlas.frame)
        col = frame % grid
        row = frame // grid
        cell_w = float(texture.width) / float(grid)
        cell_h = float(texture.height) / float(grid)
        return rl.Rectangle(
            cell_w * float(col),
            cell_h * float(row),
            max(0.0, cell_w - 2.0),
            max(0.0, cell_h - 2.0),
        )

    def _build_draw_context(
        self,
        *,
        camera: Vec2,
        view_scale: Vec2,
        scale: float,
        entity_alpha: float,
    ) -> _WorldDrawContext:
        trooper_asset = CREATURE_ASSET.get(CreatureTypeId.TROOPER)
        trooper_texture = self.creature_textures.get(trooper_asset) if trooper_asset is not None else None
        particles_texture = self.particles_texture
        monster_vision = bool(self.players) and perk_active(self.players[0], PerkId.MONSTER_VISION)
        monster_vision_src = None
        if monster_vision and particles_texture is not None:
            monster_vision_src = self._effect_src_rect(particles_texture, EffectId.AURA)
        poison_src = None
        if particles_texture is not None:
            # Native uses `effect_select_texture(0x10)` (EffectId.AURA) for creature overlays
            # (monster vision, shadow, poison aura).
            poison_src = self._effect_src_rect(particles_texture, EffectId.AURA)
        return _WorldDrawContext(
            camera=camera,
            view_scale=view_scale,
            scale=scale,
            entity_alpha=entity_alpha,
            trooper_texture=trooper_texture,
            particles_texture=particles_texture,
            monster_vision=monster_vision,
            monster_vision_src=monster_vision_src,
            poison_src=poison_src,
        )

    def _draw_player(self, player: PlayerState, *, ctx: _WorldDrawContext) -> None:
        if ctx.trooper_texture is not None:
            self._draw_player_trooper_sprite(
                ctx.trooper_texture,
                player,
                camera=ctx.camera,
                view_scale=ctx.view_scale,
                scale=ctx.scale,
                alpha=ctx.entity_alpha,
            )
            return
        screen = self._world_to_screen_with(player.pos, camera=ctx.camera, view_scale=ctx.view_scale)
        tint = rl.Color(90, 190, 120, int(255 * ctx.entity_alpha + 0.5))
        rl.draw_circle(int(screen.x), int(screen.y), max(1.0, 14.0 * ctx.scale), tint)

    def _draw_players(self, *, ctx: _WorldDrawContext, alive: bool) -> None:
        for player in self.players:
            if alive and player.health <= 0.0:
                continue
            if not alive and player.health > 0.0:
                continue
            self._draw_player(player, ctx=ctx)

    def _sorted_active_creatures(self) -> list[tuple[int, Any]]:
        creature_type_order = {
            int(CreatureTypeId.ZOMBIE): 0,
            int(CreatureTypeId.SPIDER_SP1): 1,
            int(CreatureTypeId.SPIDER_SP2): 2,
            int(CreatureTypeId.ALIEN): 3,
            int(CreatureTypeId.LIZARD): 4,
        }
        creatures = [(idx, creature) for idx, creature in enumerate(self.creatures.entries) if creature.active]
        creatures.sort(
            key=lambda item: (creature_type_order.get(int(getattr(item[1], "type_id", -1)), 999), item[0])
        )
        return creatures

    def _draw_creature_overlays(
        self,
        creature: Any,
        *,
        screen: Vec2,
        hitbox_size: float,
        ctx: _WorldDrawContext,
    ) -> None:
        if (
            ctx.particles_texture is not None
            and ctx.poison_src is not None
            and (creature.flags & CreatureFlags.SELF_DAMAGE_TICK)
        ):
            fade = monster_vision_fade_alpha(hitbox_size)
            poison_alpha = fade * ctx.entity_alpha
            if poison_alpha > 1e-3:
                size = 60.0 * ctx.scale
                dst = rl.Rectangle(screen.x, screen.y, size, size)
                origin = rl.Vector2(size * 0.5, size * 0.5)
                tint = rl.Color(255, 0, 0, int(clamp(poison_alpha, 0.0, 1.0) * 255.0 + 0.5))
                rl.draw_texture_pro(ctx.particles_texture, ctx.poison_src, dst, origin, 0.0, tint)
        if ctx.monster_vision and ctx.particles_texture is not None and ctx.monster_vision_src is not None:
            fade = monster_vision_fade_alpha(hitbox_size)
            mv_alpha = fade * ctx.entity_alpha
            if mv_alpha > 1e-3:
                size = 90.0 * ctx.scale
                dst = rl.Rectangle(screen.x, screen.y, size, size)
                origin = rl.Vector2(size * 0.5, size * 0.5)
                tint = rl.Color(255, 255, 0, int(clamp(mv_alpha, 0.0, 1.0) * 255.0 + 0.5))
                rl.draw_texture_pro(ctx.particles_texture, ctx.monster_vision_src, dst, origin, 0.0, tint)

    def _draw_creatures(self, *, ctx: _WorldDrawContext) -> None:
        for _idx, creature in self._sorted_active_creatures():
            screen = self._world_to_screen_with(creature.pos, camera=ctx.camera, view_scale=ctx.view_scale)
            hitbox_size = float(creature.hitbox_size)
            try:
                type_id = CreatureTypeId(int(creature.type_id))
            except ValueError:
                type_id = None
            asset = CREATURE_ASSET.get(type_id) if type_id is not None else None
            texture = self.creature_textures.get(asset) if asset is not None else None
            self._draw_creature_overlays(creature, screen=screen, hitbox_size=hitbox_size, ctx=ctx)
            if texture is None:
                tint = rl.Color(220, 90, 90, int(255 * ctx.entity_alpha + 0.5))
                rl.draw_circle(int(screen.x), int(screen.y), max(1.0, creature.size * 0.5 * ctx.scale), tint)
                continue

            info = CREATURE_ANIM.get(type_id) if type_id is not None else None
            if info is None:
                continue

            tint_rgba = creature.tint

            # Energizer: tint "weak" creatures blue-ish while active.
            # Mirrors `creature_render_type` (0x00418b60) branch when
            # `_bonus_energizer_timer > 0` and `max_health < 500`.
            energizer_timer = float(self.state.bonuses.energizer)
            if energizer_timer > 0.0 and float(getattr(creature, "max_hp", 0.0)) < 500.0:
                # Native clamps to 1.0, then blends towards (0.5, 0.5, 1.0, 1.0).
                # Effect is full strength while timer >= 1 and fades out during the last second.
                t = energizer_timer
                if t >= 1.0:
                    t = 1.0
                elif t < 0.0:
                    t = 0.0
                tint_rgba = RGBA.lerp(tint_rgba, RGBA(0.5, 0.5, 1.0, 1.0), t)
            if hitbox_size < 0.0:
                # Mirrors the main-pass alpha fade when hitbox_size ramps negative.
                tint_rgba = tint_rgba.with_alpha(max(0.0, tint_rgba.a + hitbox_size * 0.1))
            tint = tint_rgba.scaled_alpha(ctx.entity_alpha).clamped().to_rl()

            size_scale = clamp(float(creature.size) / 64.0, 0.25, 2.0)
            fx_detail = self.config.fx_detail(level=0, default=True) if self.config is not None else True
            # Mirrors `creature_render_type`: the "shadow-ish" pass is gated by fx_detail_0
            # and is disabled when the Monster Vision perk is active.
            shadow = fx_detail and (not self.players or not perk_active(self.players[0], PerkId.MONSTER_VISION))
            long_strip = (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0 or (
                creature.flags & CreatureFlags.ANIM_LONG_STRIP
            ) != 0
            phase = float(creature.anim_phase)
            if long_strip:
                if hitbox_size < 0.0:
                    # Negative phase selects the fallback "corpse" frame in creature_render_type.
                    phase = -1.0
                elif hitbox_size < 16.0:
                    # Death staging: while hitbox_size ramps down (16..0), creature_render_type
                    # selects frames via `__ftol((base_frame + 15) - hitbox_size)`.
                    phase = float(info.base + 0x0F) - hitbox_size - 0.5

            shadow_alpha = None
            if shadow:
                # Shadow pass uses tint_a * 0.4 and fades much faster for corpses (hitbox_size < 0).
                shadow_a = float(creature.tint.a) * 0.4
                if hitbox_size < 0.0:
                    shadow_a += hitbox_size * (0.5 if long_strip else 0.1)
                    shadow_a = max(0.0, shadow_a)
                shadow_alpha = int(clamp(shadow_a * ctx.entity_alpha * 255.0, 0.0, 255.0) + 0.5)
            self._draw_creature_sprite(
                texture,
                type_id=type_id or CreatureTypeId.ZOMBIE,
                flags=creature.flags,
                phase=phase,
                mirror_long=bool(info.mirror) and hitbox_size >= 16.0,
                shadow_alpha=shadow_alpha,
                pos=creature.pos,
                rotation_rad=float(creature.heading) - math.pi / 2.0,
                scale=ctx.scale,
                size_scale=size_scale,
                tint=tint,
                shadow=shadow,
            )

    def _draw_freeze_overlay(self, *, ctx: _WorldDrawContext) -> None:
        if ctx.particles_texture is None:
            return
        freeze_timer = float(self.state.bonuses.freeze)
        if freeze_timer <= 0.0:
            return
        src = self._effect_src_rect(ctx.particles_texture, EffectId.FREEZE_SHATTER)
        if src is None:
            return

        fade = 1.0 if freeze_timer >= 1.0 else clamp(freeze_timer, 0.0, 1.0)
        freeze_alpha = clamp(fade * ctx.entity_alpha * 0.7, 0.0, 1.0)
        if freeze_alpha <= 1e-3:
            return
        tint = rl.Color(255, 255, 255, int(freeze_alpha * 255.0 + 0.5))
        rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
        for idx, creature in enumerate(self.creatures.entries):
            if not creature.active:
                continue
            size = float(creature.size) * ctx.scale
            if size <= 1e-3:
                continue
            creature_screen = self._world_to_screen_with(
                creature.pos,
                camera=ctx.camera,
                view_scale=ctx.view_scale,
            )
            dst = rl.Rectangle(creature_screen.x, creature_screen.y, size, size)
            origin = rl.Vector2(size * 0.5, size * 0.5)
            rotation_deg = (float(idx) * 0.01 + float(creature.heading)) * _RAD_TO_DEG
            rl.draw_texture_pro(ctx.particles_texture, src, dst, origin, rotation_deg, tint)
        rl.end_blend_mode()

    def _draw_projectiles_and_effects(self, *, ctx: _WorldDrawContext) -> None:
        self._draw_sharpshooter_laser_sight(
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            scale=ctx.scale,
            alpha=ctx.entity_alpha,
        )
        for proj_index, proj in enumerate(self.state.projectiles.entries):
            if not proj.active:
                continue
            self._draw_projectile(proj, proj_index=proj_index, scale=ctx.scale, alpha=ctx.entity_alpha)
        self._draw_particle_pool(camera=ctx.camera, view_scale=ctx.view_scale, alpha=ctx.entity_alpha)
        for proj in self.state.secondary_projectiles.entries:
            if not proj.active:
                continue
            self._draw_secondary_projectile(proj, scale=ctx.scale, alpha=ctx.entity_alpha)
        self._draw_sprite_effect_pool(camera=ctx.camera, view_scale=ctx.view_scale, alpha=ctx.entity_alpha)
        self._draw_effect_pool(camera=ctx.camera, view_scale=ctx.view_scale, alpha=ctx.entity_alpha)

    def _draw_aim_indicators(self, *, ctx: _WorldDrawContext) -> None:
        for player in self.players:
            if player.health <= 0.0:
                continue
            aim = player.aim
            dist = player.pos.distance_to(player.aim)
            radius = max(6.0, dist * float(getattr(player, "spread_heat", 0.0)) * 0.5)
            aim_screen = self._world_to_screen_with(aim, camera=ctx.camera, view_scale=ctx.view_scale)
            screen_radius = max(1.0, radius * ctx.scale)
            self._draw_aim_circle(center=aim_screen, radius=screen_radius, alpha=ctx.entity_alpha)
            reload_timer = float(getattr(player, "reload_timer", 0.0))
            reload_max = float(getattr(player, "reload_timer_max", 0.0))
            if reload_max > 1e-6 and reload_timer > 1e-6:
                progress = reload_timer / reload_max
                if progress > 0.0:
                    ms = int(progress * 60000.0)
                    self._draw_clock_gauge(
                        pos=Vec2(int(aim_screen.x), int(aim_screen.y)),
                        ms=ms,
                        scale=ctx.scale,
                        alpha=ctx.entity_alpha,
                    )

    def _draw_bonus_and_ui(self, *, ctx: _WorldDrawContext, draw_aim_indicators: bool) -> None:
        self._draw_bonus_pickups(
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            scale=ctx.scale,
            alpha=ctx.entity_alpha,
        )
        self._draw_bonus_hover_labels(camera=ctx.camera, view_scale=ctx.view_scale, alpha=ctx.entity_alpha)
        if draw_aim_indicators and (not self.demo_mode_active):
            self._draw_aim_indicators(ctx=ctx)
        self._draw_direction_arrows(
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            scale=ctx.scale,
            alpha=ctx.entity_alpha,
        )
