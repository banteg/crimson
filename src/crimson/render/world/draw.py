from __future__ import annotations

import math
from collections.abc import Callable
from typing import TYPE_CHECKING

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rl
from grim.terrain_render import _maybe_alpha_test

from ...creatures.spawn import CreatureFlags, CreatureTypeId
from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, SIZE_CODE_GRID, EffectId
from ...perks import PerkId
from ...perks.helpers import perk_active
from ...sim.world_defs import CREATURE_ANIM, CREATURE_ASSET
from ...ui.cursor import draw_aim_cursor
from .bonuses import draw_bonus_hover_labels, draw_bonus_pickups
from .constants import _RAD_TO_DEG, monster_vision_fade_alpha
from .context import WorldRenderCtx
from .creatures import draw_creature_sprite
from .effects import draw_effect_pool, draw_particle_pool, draw_sprite_effect_pool
from .overlays import draw_aim_circle, draw_clock_gauge, draw_direction_arrows
from .profile_hooks import profile_pass
from .projectiles import draw_projectile, draw_secondary_projectile, draw_sharpshooter_laser_sight
from .trooper import draw_player_trooper_sprite

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureState
    from ...sim.state_types import PlayerState

class WorldDrawContext(msgspec.Struct, frozen=True):
    camera: Vec2 = Vec2()
    view_scale: Vec2 = Vec2(1.0, 1.0)
    scale: float = 1.0
    entity_alpha: float = 1.0
    trooper_texture: rl.Texture | None = None
    particles_texture: rl.Texture | None = None
    monster_vision: bool = False
    monster_vision_src: rl.Rectangle | None = None
    poison_src: rl.Rectangle | None = None


type _WorldToScreenWithFn = Callable[[Vec2, Vec2, Vec2], Vec2]
type _DrawAimCircleFn = Callable[[Vec2, float, float], None]
type _DrawClockGaugeFn = Callable[[Vec2, int, float, float], None]


def draw_world(
    render_ctx: WorldRenderCtx,
    *,
    draw_aim_indicators: bool = True,
    entity_alpha: float = 1.0,
) -> None:
    entity_alpha = clamp(float(entity_alpha), 0.0, 1.0)
    camera, view_scale, scale, screen_size, out_size = compute_view_transform(render_ctx)
    with profile_pass("background"):
        draw_background(render_ctx, camera=camera, screen_size=screen_size, out_size=out_size, view_scale=view_scale)
    if entity_alpha <= 1e-3:
        return

    with _maybe_alpha_test(bool(alpha_test_enabled(render_ctx))):
        draw_ctx = build_draw_context(
            render_ctx,
            camera=camera,
            view_scale=view_scale,
            scale=scale,
            entity_alpha=entity_alpha,
        )
        with profile_pass("players_dead"):
            draw_players(render_ctx, ctx=draw_ctx, alive=False)
        with profile_pass("creatures"):
            draw_creatures(render_ctx, ctx=draw_ctx)
        with profile_pass("freeze_overlay"):
            draw_freeze_overlay(render_ctx, ctx=draw_ctx)
        with profile_pass("players_alive"):
            draw_players(render_ctx, ctx=draw_ctx, alive=True)
        with profile_pass("projectiles_effects"):
            draw_projectiles_and_effects(render_ctx, ctx=draw_ctx)
        with profile_pass("bonus_ui"):
            draw_bonus_and_ui(render_ctx, ctx=draw_ctx, draw_aim_indicators_enabled=draw_aim_indicators)


def compute_view_transform(render_ctx: WorldRenderCtx) -> tuple[Vec2, Vec2, float, Vec2, Vec2]:
    out_w = float(rl.get_screen_width())
    out_h = float(rl.get_screen_height())
    out_size = Vec2(out_w, out_h)
    screen_size = render_ctx._camera_screen_size(runtime_w=out_w, runtime_h=out_h)
    camera = render_ctx._clamp_camera(render_ctx.camera, screen_size)
    scale_x = out_w / screen_size.x if screen_size.x > 0 else 1.0
    scale_y = out_h / screen_size.y if screen_size.y > 0 else 1.0
    view_scale = Vec2(scale_x, scale_y)
    scale = render_ctx._view_scale_avg(view_scale)
    return camera, view_scale, scale, screen_size, out_size


def draw_background(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    screen_size: Vec2,
    out_size: Vec2,
    view_scale: Vec2,
) -> None:
    clear_color = rl.Color(10, 10, 12, 255)
    ground = render_ctx.ground
    rl.clear_background(clear_color)
    if ground is not None:
        ground.draw(
            camera,
            screen_w=screen_size.x,
            screen_h=screen_size.y,
            out_w=out_size.x,
            out_h=out_size.y,
        )
        return

    # World bounds for debug if terrain is missing.
    world_min = camera.mul_components(view_scale)
    world_max = (camera + Vec2(float(render_ctx.world_size), float(render_ctx.world_size))).mul_components(view_scale)
    rl.draw_rectangle_lines(
        int(world_min.x),
        int(world_min.y),
        int(world_max.x - world_min.x),
        int(world_max.y - world_min.y),
        rl.Color(40, 40, 55, 255),
    )


def alpha_test_enabled(render_ctx: WorldRenderCtx) -> bool:
    ground = render_ctx.ground
    if ground is None:
        return True
    return ground.alpha_test


def effect_src_rect(texture: rl.Texture, effect_id: EffectId) -> rl.Rectangle | None:
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


def build_draw_context(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    view_scale: Vec2,
    scale: float,
    entity_alpha: float,
) -> WorldDrawContext:
    trooper_asset = CREATURE_ASSET.get(CreatureTypeId.TROOPER)
    trooper_texture = render_ctx.creature_textures.get(trooper_asset) if trooper_asset is not None else None
    particles_texture = render_ctx.particles_texture

    monster_vision = bool(render_ctx.players) and perk_active(render_ctx.players[0], PerkId.MONSTER_VISION)
    monster_vision_src = None
    if monster_vision and particles_texture is not None:
        monster_vision_src = effect_src_rect(particles_texture, EffectId.AURA)

    poison_src = None
    if particles_texture is not None:
        # Native uses `effect_select_texture(0x10)` (EffectId.AURA) for creature overlays
        # (monster vision, shadow, poison aura).
        poison_src = effect_src_rect(particles_texture, EffectId.AURA)

    return WorldDrawContext(
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


def draw_player(render_ctx: WorldRenderCtx, player: PlayerState, *, ctx: WorldDrawContext) -> None:
    if ctx.trooper_texture is not None:
        draw_player_trooper_sprite(
            render_ctx,
            ctx.trooper_texture,
            player,
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            scale=ctx.scale,
            alpha=ctx.entity_alpha,
        )
        return

    screen = render_ctx._world_to_screen_with(player.pos, camera=ctx.camera, view_scale=ctx.view_scale)
    tint = rl.Color(90, 190, 120, int(255 * ctx.entity_alpha + 0.5))
    rl.draw_circle(int(screen.x), int(screen.y), max(1.0, 14.0 * ctx.scale), tint)


def draw_players(render_ctx: WorldRenderCtx, *, ctx: WorldDrawContext, alive: bool) -> None:
    for player in render_ctx.players:
        if alive and player.health <= 0.0:
            continue
        if not alive and player.health > 0.0:
            continue
        draw_player(render_ctx, player, ctx=ctx)


def sorted_active_creatures(render_ctx: WorldRenderCtx) -> list[tuple[int, CreatureState]]:
    creature_type_order = {
        CreatureTypeId.ZOMBIE: 0,
        CreatureTypeId.SPIDER_SP1: 1,
        CreatureTypeId.SPIDER_SP2: 2,
        CreatureTypeId.ALIEN: 3,
        CreatureTypeId.LIZARD: 4,
        CreatureTypeId.TROOPER: 5,
    }
    creatures = [(idx, creature) for idx, creature in enumerate(render_ctx.creatures.entries) if creature.active]
    creatures.sort(
        key=lambda item: (creature_type_order[item[1].type_id], item[0]),
    )
    return creatures


def draw_creature_overlays(
    render_ctx: WorldRenderCtx,
    creature: CreatureState,
    *,
    screen: Vec2,
    lifecycle_stage: float,
    ctx: WorldDrawContext,
) -> None:
    fade = monster_vision_fade_alpha(lifecycle_stage)
    if ctx.monster_vision and ctx.particles_texture is not None and ctx.monster_vision_src is not None:
        mv_alpha = fade * ctx.entity_alpha
        if mv_alpha > 1e-3:
            size = 90.0 * ctx.scale
            dst = rl.Rectangle(screen.x, screen.y, size, size)
            origin = rl.Vector2(size * 0.5, size * 0.5)
            tint = rl.Color(255, 255, 0, int(clamp(mv_alpha, 0.0, 1.0) * 255.0 + 0.5))
            rl.draw_texture_pro(ctx.particles_texture, ctx.monster_vision_src, dst, origin, 0.0, tint)

    if ctx.particles_texture is not None and ctx.poison_src is not None and bool(creature.plague_infected):
        # creature_render_all: collision_flag overlay (black 80x80 aura), drawn before red poison flag.
        plague_alpha = fade * ctx.entity_alpha
        if plague_alpha > 1e-3:
            size = 80.0 * ctx.scale
            dst = rl.Rectangle(screen.x, screen.y, size, size)
            origin = rl.Vector2(size * 0.5, size * 0.5)
            tint = rl.Color(0, 0, 0, int(clamp(plague_alpha, 0.0, 1.0) * 255.0 + 0.5))
            rl.draw_texture_pro(ctx.particles_texture, ctx.poison_src, dst, origin, 0.0, tint)

    if (
        ctx.particles_texture is not None
        and ctx.poison_src is not None
        and (creature.flags & CreatureFlags.SELF_DAMAGE_TICK)
    ):
        poison_alpha = fade * ctx.entity_alpha
        if poison_alpha > 1e-3:
            size = 60.0 * ctx.scale
            dst = rl.Rectangle(screen.x, screen.y, size, size)
            origin = rl.Vector2(size * 0.5, size * 0.5)
            tint = rl.Color(255, 0, 0, int(clamp(poison_alpha, 0.0, 1.0) * 255.0 + 0.5))
            rl.draw_texture_pro(ctx.particles_texture, ctx.poison_src, dst, origin, 0.0, tint)


def draw_creatures(render_ctx: WorldRenderCtx, *, ctx: WorldDrawContext) -> None:
    for _idx, creature in sorted_active_creatures(render_ctx):
        screen = render_ctx._world_to_screen_with(creature.pos, camera=ctx.camera, view_scale=ctx.view_scale)
        lifecycle_stage = float(creature.lifecycle_stage)

        type_id = creature.type_id
        asset = CREATURE_ASSET[type_id]
        texture = render_ctx.creature_textures.get(asset)

        draw_creature_overlays(render_ctx, creature, screen=screen, lifecycle_stage=lifecycle_stage, ctx=ctx)

        if texture is None:
            tint = rl.Color(220, 90, 90, int(255 * ctx.entity_alpha + 0.5))
            rl.draw_circle(int(screen.x), int(screen.y), max(1.0, creature.size * 0.5 * ctx.scale), tint)
            continue

        info = CREATURE_ANIM[type_id]

        tint_rgba = creature.tint

        # Energizer: tint "weak" creatures blue-ish while active.
        # Mirrors `creature_render_type` (0x00418b60) branch when
        # `_bonus_energizer_timer > 0` and `max_health < 500`.
        energizer_timer = float(render_ctx.state.bonuses.energizer)
        if energizer_timer > 0.0 and float(creature.max_hp) < 500.0:
            # Native clamps to 1.0, then blends towards (0.5, 0.5, 1.0, 1.0).
            # Effect is full strength while timer >= 1 and fades out during the last second.
            t = energizer_timer
            if t >= 1.0:
                t = 1.0
            elif t < 0.0:
                t = 0.0
            tint_rgba = RGBA.lerp(tint_rgba, RGBA(0.5, 0.5, 1.0, 1.0), t)

        if lifecycle_stage < 0.0:
            # Mirrors the main-pass alpha fade when lifecycle_stage ramps negative.
            tint_rgba = tint_rgba.with_alpha(max(0.0, tint_rgba.a + lifecycle_stage * 0.1))

        tint = tint_rgba.scaled_alpha(ctx.entity_alpha).clamped().to_rl()

        size_scale = clamp(float(creature.size) / 64.0, 0.25, 2.0)
        fx_detail = render_ctx.config.fx_detail(level=0, default=True) if render_ctx.config is not None else True
        # Mirrors `creature_render_type`: the "shadow-ish" pass is gated by fx_detail_0
        # and is disabled when the Monster Vision perk is active.
        shadow = fx_detail and (not render_ctx.players or not perk_active(render_ctx.players[0], PerkId.MONSTER_VISION))
        long_strip = (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0 or (
            creature.flags & CreatureFlags.ANIM_LONG_STRIP
        ) != 0

        phase = float(creature.anim_phase)
        if long_strip:
            if lifecycle_stage < 0.0:
                # Negative phase selects the fallback "corpse" frame in creature_render_type.
                phase = -1.0
            elif lifecycle_stage < 16.0:
                # Death staging: while lifecycle_stage ramps down (16..0), creature_render_type
                # selects frames via `__ftol((base_frame + 15) - lifecycle_stage)`.
                phase = float(info.base + 0x0F) - lifecycle_stage - 0.5

        shadow_alpha = None
        if shadow:
            # Shadow pass uses tint_a * 0.4 and fades much faster for corpses (lifecycle_stage < 0).
            shadow_a = float(creature.tint.a) * 0.4
            if lifecycle_stage < 0.0:
                shadow_a += lifecycle_stage * (0.5 if long_strip else 0.1)
                shadow_a = max(0.0, shadow_a)
            shadow_alpha = int(clamp(shadow_a * ctx.entity_alpha * 255.0, 0.0, 255.0) + 0.5)

        draw_creature_sprite(
            render_ctx,
            texture,
            type_id=type_id or CreatureTypeId.ZOMBIE,
            flags=creature.flags,
            phase=phase,
            mirror_long=bool(info.mirror) and lifecycle_stage >= 16.0,
            shadow_alpha=shadow_alpha,
            pos=creature.pos,
            screen_pos=screen,
            rotation_rad=float(creature.heading) - math.pi / 2.0,
            scale=ctx.scale,
            size_scale=size_scale,
            tint=tint,
            shadow=shadow,
        )


def draw_freeze_overlay(render_ctx: WorldRenderCtx, *, ctx: WorldDrawContext) -> None:
    if ctx.particles_texture is None:
        return

    freeze_timer = float(render_ctx.state.bonuses.freeze)
    if freeze_timer <= 0.0:
        return

    src = effect_src_rect(ctx.particles_texture, EffectId.FREEZE_SHATTER)
    if src is None:
        return

    fade = 1.0 if freeze_timer >= 1.0 else clamp(freeze_timer, 0.0, 1.0)
    freeze_alpha = clamp(fade * ctx.entity_alpha * 0.7, 0.0, 1.0)
    if freeze_alpha <= 1e-3:
        return

    tint = rl.Color(255, 255, 255, int(freeze_alpha * 255.0 + 0.5))
    rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)
    for idx, creature in enumerate(render_ctx.creatures.entries):
        if not creature.active:
            continue
        size = float(creature.size) * ctx.scale
        if size <= 1e-3:
            continue
        creature_screen = render_ctx._world_to_screen_with(
            creature.pos,
            camera=ctx.camera,
            view_scale=ctx.view_scale,
        )
        dst = rl.Rectangle(creature_screen.x, creature_screen.y, size, size)
        origin = rl.Vector2(size * 0.5, size * 0.5)
        rotation_deg = (float(idx) * 0.01 + float(creature.heading)) * _RAD_TO_DEG
        rl.draw_texture_pro(ctx.particles_texture, src, dst, origin, rotation_deg, tint)
    rl.end_blend_mode()


def draw_projectiles_and_effects(render_ctx: WorldRenderCtx, *, ctx: WorldDrawContext) -> None:
    with profile_pass("laser_sight"):
        draw_sharpshooter_laser_sight(
            render_ctx,
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            scale=ctx.scale,
            alpha=ctx.entity_alpha,
        )

    with profile_pass("primary_projectiles"):
        for proj_index, proj in enumerate(render_ctx.state.projectiles.entries):
            if not proj.active:
                continue
            draw_projectile(
                render_ctx,
                proj,
                proj_index=proj_index,
                camera=ctx.camera,
                view_scale=ctx.view_scale,
                scale=ctx.scale,
                alpha=ctx.entity_alpha,
            )

    with profile_pass("particle_pool"):
        draw_particle_pool(
            render_ctx,
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            alpha=ctx.entity_alpha,
        )

    with profile_pass("secondary_projectiles"):
        for proj in render_ctx.state.secondary_projectiles.entries:
            if not proj.active:
                continue
            draw_secondary_projectile(
                render_ctx,
                proj,
                camera=ctx.camera,
                view_scale=ctx.view_scale,
                scale=ctx.scale,
                alpha=ctx.entity_alpha,
            )

    with profile_pass("sprite_effect_pool"):
        draw_sprite_effect_pool(
            render_ctx,
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            alpha=ctx.entity_alpha,
        )
    with profile_pass("effect_pool"):
        draw_effect_pool(
            render_ctx,
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            alpha=ctx.entity_alpha,
        )


def iter_visible_aim_players(render_ctx: WorldRenderCtx) -> tuple[PlayerState, ...]:
    players = render_ctx.players
    if not bool(render_ctx.lan_local_aim_indicators_only):
        return tuple(players)
    local_slot = int(render_ctx.lan_local_player_slot_index)
    return tuple(player for player in players if int(player.index) == local_slot)


def draw_aim_indicators(
    render_ctx: WorldRenderCtx,
    *,
    ctx: WorldDrawContext,
    world_to_screen_with: _WorldToScreenWithFn | None = None,
    draw_aim_circle_fn: _DrawAimCircleFn | None = None,
    draw_clock_gauge_fn: _DrawClockGaugeFn | None = None,
) -> None:
    transform = world_to_screen_with
    if transform is None:
        def transform(pos: Vec2, camera: Vec2, view_scale: Vec2) -> Vec2:
            return render_ctx._world_to_screen_with(
                pos,
                camera=camera,
                view_scale=view_scale,
            )

    draw_circle = draw_aim_circle_fn
    if draw_circle is None:
        def draw_circle(center: Vec2, radius: float, alpha: float) -> None:
            draw_aim_circle(
                render_ctx,
                center=center,
                radius=radius,
                alpha=alpha,
            )

    draw_gauge = draw_clock_gauge_fn
    if draw_gauge is None:
        def draw_gauge(pos: Vec2, ms: int, scale: float, alpha: float) -> None:
            draw_clock_gauge(
                render_ctx,
                pos=pos,
                ms=ms,
                scale=scale,
                alpha=alpha,
            )

    for player in iter_visible_aim_players(render_ctx):
        if player.health <= 0.0:
            continue

        aim = player.aim
        dist = player.pos.distance_to(player.aim)
        radius = max(6.0, dist * float(player.spread_heat) * 0.5)
        aim_screen = transform(aim, ctx.camera, ctx.view_scale)
        screen_radius = max(1.0, radius * ctx.scale)
        draw_circle(aim_screen, screen_radius, ctx.entity_alpha)

        reload_timer = float(player.weapon.reload_timer)
        reload_max = float(player.weapon.reload_timer_max)
        if reload_max > 1e-6 and reload_timer > 1e-6:
            progress = reload_timer / reload_max
            if progress > 0.0:
                ms = int(progress * 60000.0)
                draw_gauge(Vec2(int(aim_screen.x), int(aim_screen.y)), ms, ctx.scale, ctx.entity_alpha)


def draw_aim_enhancements(
    render_ctx: WorldRenderCtx,
    *,
    ctx: WorldDrawContext,
    world_to_screen_with: _WorldToScreenWithFn | None = None,
) -> None:
    transform = world_to_screen_with
    if transform is None:
        def transform(pos: Vec2, camera: Vec2, view_scale: Vec2) -> Vec2:
            return render_ctx._world_to_screen_with(
                pos,
                camera=camera,
                view_scale=view_scale,
            )

    for player in iter_visible_aim_players(render_ctx):
        if player.health <= 0.0:
            continue
        aim_screen = transform(player.aim, ctx.camera, ctx.view_scale)
        draw_aim_cursor(ctx.particles_texture, render_ctx.aim_texture, pos=aim_screen)


def draw_bonus_and_ui(
    render_ctx: WorldRenderCtx,
    *,
    ctx: WorldDrawContext,
    draw_aim_indicators_enabled: bool,
) -> None:
    with profile_pass("bonus_pickups"):
        draw_bonus_pickups(
            render_ctx,
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            scale=ctx.scale,
            alpha=ctx.entity_alpha,
        )
    with profile_pass("bonus_labels"):
        draw_bonus_hover_labels(
            render_ctx,
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            alpha=ctx.entity_alpha,
        )

    draw_world_aim = draw_aim_indicators_enabled and (not render_ctx.demo_mode_active)
    if draw_world_aim:
        with profile_pass("aim_indicators"):
            draw_aim_indicators(render_ctx, ctx=ctx)

    with profile_pass("direction_arrows"):
        draw_direction_arrows(
            render_ctx,
            camera=ctx.camera,
            view_scale=ctx.view_scale,
            scale=ctx.scale,
            alpha=ctx.entity_alpha,
        )

    if draw_world_aim:
        with profile_pass("aim_enhancements"):
            draw_aim_enhancements(render_ctx, ctx=ctx)


__all__ = [
    "WorldDrawContext",
    "draw_aim_enhancements",
    "draw_aim_indicators",
    "draw_world",
]
