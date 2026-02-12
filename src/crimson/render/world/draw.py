from __future__ import annotations

import math
from typing import TYPE_CHECKING

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
        clear_color = rl.Color(10, 10, 12, 255)
        screen_size = self._camera_screen_size()
        camera = self._clamp_camera(self.camera, screen_size)
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        scale_x = out_w / screen_size.x if screen_size.x > 0 else 1.0
        scale_y = out_h / screen_size.y if screen_size.y > 0 else 1.0
        view_scale = Vec2(scale_x, scale_y)
        if self.ground is None:
            rl.clear_background(clear_color)
        else:
            rl.clear_background(clear_color)
            self.ground.draw(camera, screen_w=screen_size.x, screen_h=screen_size.y)
        scale = self._view_scale_avg(view_scale)

        # World bounds for debug if terrain is missing.
        if self.ground is None:
            world_min = camera.mul_components(view_scale)
            world_max = (camera + Vec2(float(self.world_size), float(self.world_size))).mul_components(view_scale)
            rl.draw_rectangle_lines(
                int(world_min.x),
                int(world_min.y),
                int(world_max.x - world_min.x),
                int(world_max.y - world_min.y),
                rl.Color(40, 40, 55, 255),
            )

        if entity_alpha <= 1e-3:
            return

        alpha_test = True
        if self.ground is not None:
            alpha_test = bool(getattr(self.ground, "alpha_test", True))

        with _maybe_alpha_test(bool(alpha_test)):
            trooper_asset = CREATURE_ASSET.get(CreatureTypeId.TROOPER)
            trooper_texture = self.creature_textures.get(trooper_asset) if trooper_asset is not None else None
            particles_texture = self.particles_texture
            monster_vision = bool(self.players) and perk_active(self.players[0], PerkId.MONSTER_VISION)
            monster_vision_src: rl.Rectangle | None = None
            if monster_vision and particles_texture is not None:
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.AURA))
                if atlas is not None:
                    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                    if grid:
                        frame = int(atlas.frame)
                        col = frame % grid
                        row = frame // grid
                        cell_w = float(particles_texture.width) / float(grid)
                        cell_h = float(particles_texture.height) / float(grid)
                        monster_vision_src = rl.Rectangle(
                            cell_w * float(col),
                            cell_h * float(row),
                            max(0.0, cell_w - 2.0),
                            max(0.0, cell_h - 2.0),
                        )
            poison_src: rl.Rectangle | None = None
            if particles_texture is not None:
                # Native uses `effect_select_texture(0x10)` (EffectId.AURA) for creature overlays
                # (monster vision, shadow, poison aura).
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.AURA))
                if atlas is not None:
                    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                    if grid:
                        frame = int(atlas.frame)
                        col = frame % grid
                        row = frame // grid
                        cell_w = float(particles_texture.width) / float(grid)
                        cell_h = float(particles_texture.height) / float(grid)
                        poison_src = rl.Rectangle(
                            cell_w * float(col),
                            cell_h * float(row),
                            max(0.0, cell_w - 2.0),
                            max(0.0, cell_h - 2.0),
                        )

            def draw_player(player: PlayerState) -> None:
                if trooper_texture is not None:
                    self._draw_player_trooper_sprite(
                        trooper_texture,
                        player,
                        camera=camera,
                        view_scale=view_scale,
                        scale=scale,
                        alpha=entity_alpha,
                    )
                    return

                screen = self._world_to_screen_with(player.pos, camera=camera, view_scale=view_scale)
                tint = rl.Color(90, 190, 120, int(255 * entity_alpha + 0.5))
                rl.draw_circle(int(screen.x), int(screen.y), max(1.0, 14.0 * scale), tint)

            for player in self.players:
                if player.health <= 0.0:
                    draw_player(player)

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
            for _idx, creature in creatures:
                screen = self._world_to_screen_with(creature.pos, camera=camera, view_scale=view_scale)
                hitbox_size = float(creature.hitbox_size)
                try:
                    type_id = CreatureTypeId(int(creature.type_id))
                except ValueError:
                    type_id = None
                asset = CREATURE_ASSET.get(type_id) if type_id is not None else None
                texture = self.creature_textures.get(asset) if asset is not None else None
                if (
                    particles_texture is not None
                    and poison_src is not None
                    and (creature.flags & CreatureFlags.SELF_DAMAGE_TICK)
                ):
                    fade = monster_vision_fade_alpha(hitbox_size)
                    poison_alpha = fade * entity_alpha
                    if poison_alpha > 1e-3:
                        size = 60.0 * scale
                        dst = rl.Rectangle(screen.x, screen.y, size, size)
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        tint = rl.Color(255, 0, 0, int(clamp(poison_alpha, 0.0, 1.0) * 255.0 + 0.5))
                        rl.draw_texture_pro(particles_texture, poison_src, dst, origin, 0.0, tint)
                if monster_vision and particles_texture is not None and monster_vision_src is not None:
                    fade = monster_vision_fade_alpha(hitbox_size)
                    mv_alpha = fade * entity_alpha
                    if mv_alpha > 1e-3:
                        size = 90.0 * scale
                        dst = rl.Rectangle(screen.x, screen.y, size, size)
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        tint = rl.Color(255, 255, 0, int(clamp(mv_alpha, 0.0, 1.0) * 255.0 + 0.5))
                        rl.draw_texture_pro(particles_texture, monster_vision_src, dst, origin, 0.0, tint)
                if texture is None:
                    tint = rl.Color(220, 90, 90, int(255 * entity_alpha + 0.5))
                    rl.draw_circle(int(screen.x), int(screen.y), max(1.0, creature.size * 0.5 * scale), tint)
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
                tint = tint_rgba.scaled_alpha(entity_alpha).clamped().to_rl()

                size_scale = clamp(float(creature.size) / 64.0, 0.25, 2.0)
                fx_detail = bool(self.config.data.get("fx_detail_0", 0)) if self.config is not None else True
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
                    shadow_alpha = int(clamp(shadow_a * entity_alpha * 255.0, 0.0, 255.0) + 0.5)
                self._draw_creature_sprite(
                    texture,
                    type_id=type_id or CreatureTypeId.ZOMBIE,
                    flags=creature.flags,
                    phase=phase,
                    mirror_long=bool(info.mirror) and hitbox_size >= 16.0,
                    shadow_alpha=shadow_alpha,
                    pos=creature.pos,
                    rotation_rad=float(creature.heading) - math.pi / 2.0,
                    scale=scale,
                    size_scale=size_scale,
                    tint=tint,
                    shadow=shadow,
                )

            freeze_timer = float(self.state.bonuses.freeze)
            if particles_texture is not None and freeze_timer > 0.0:
                atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.FREEZE_SHATTER))
                if atlas is not None:
                    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
                    if grid:
                        cell_w = float(particles_texture.width) / float(grid)
                        cell_h = float(particles_texture.height) / float(grid)
                        frame = int(atlas.frame)
                        col = frame % grid
                        row = frame // grid
                        src = rl.Rectangle(
                            cell_w * float(col),
                            cell_h * float(row),
                            max(0.0, cell_w - 2.0),
                            max(0.0, cell_h - 2.0),
                        )

                        fade = 1.0 if freeze_timer >= 1.0 else clamp(freeze_timer, 0.0, 1.0)
                        freeze_alpha = clamp(fade * entity_alpha * 0.7, 0.0, 1.0)
                        if freeze_alpha > 1e-3:
                            tint = rl.Color(255, 255, 255, int(freeze_alpha * 255.0 + 0.5))
                            rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
                            for idx, creature in enumerate(self.creatures.entries):
                                if not creature.active:
                                    continue
                                size = float(creature.size) * scale
                                if size <= 1e-3:
                                    continue
                                creature_screen = self._world_to_screen_with(
                                    creature.pos,
                                    camera=camera,
                                    view_scale=view_scale,
                                )
                                dst = rl.Rectangle(creature_screen.x, creature_screen.y, size, size)
                                origin = rl.Vector2(size * 0.5, size * 0.5)
                                rotation_deg = (float(idx) * 0.01 + float(creature.heading)) * _RAD_TO_DEG
                                rl.draw_texture_pro(particles_texture, src, dst, origin, rotation_deg, tint)
                            rl.end_blend_mode()

            for player in self.players:
                if player.health > 0.0:
                    draw_player(player)

            self._draw_sharpshooter_laser_sight(
                camera=camera,
                view_scale=view_scale,
                scale=scale,
                alpha=entity_alpha,
            )

            for proj_index, proj in enumerate(self.state.projectiles.entries):
                if not proj.active:
                    continue
                self._draw_projectile(proj, proj_index=proj_index, scale=scale, alpha=entity_alpha)

            self._draw_particle_pool(camera=camera, view_scale=view_scale, alpha=entity_alpha)

            for proj in self.state.secondary_projectiles.entries:
                if not proj.active:
                    continue
                self._draw_secondary_projectile(proj, scale=scale, alpha=entity_alpha)

            self._draw_sprite_effect_pool(camera=camera, view_scale=view_scale, alpha=entity_alpha)
            self._draw_effect_pool(camera=camera, view_scale=view_scale, alpha=entity_alpha)
            self._draw_bonus_pickups(camera=camera, view_scale=view_scale, scale=scale, alpha=entity_alpha)
            self._draw_bonus_hover_labels(camera=camera, view_scale=view_scale, alpha=entity_alpha)

            if draw_aim_indicators and (not self.demo_mode_active):
                for player in self.players:
                    if player.health <= 0.0:
                        continue
                    aim = player.aim
                    dist = player.pos.distance_to(player.aim)
                    radius = max(6.0, dist * float(getattr(player, "spread_heat", 0.0)) * 0.5)
                    aim_screen = self._world_to_screen_with(aim, camera=camera, view_scale=view_scale)
                    screen_radius = max(1.0, radius * scale)
                    self._draw_aim_circle(center=aim_screen, radius=screen_radius, alpha=entity_alpha)
                    reload_timer = float(getattr(player, "reload_timer", 0.0))
                    reload_max = float(getattr(player, "reload_timer_max", 0.0))
                    if reload_max > 1e-6 and reload_timer > 1e-6:
                        progress = reload_timer / reload_max
                        if progress > 0.0:
                            ms = int(progress * 60000.0)
                            self._draw_clock_gauge(
                                pos=Vec2(int(aim_screen.x), int(aim_screen.y)),
                                ms=ms,
                                scale=scale,
                                alpha=entity_alpha,
                            )

            self._draw_direction_arrows(
                camera=camera,
                view_scale=view_scale,
                scale=scale,
                alpha=entity_alpha,
            )
