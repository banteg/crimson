from __future__ import annotations

from grim.assets import RuntimeResources, TextureId
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer

from ..game.types import GameState
from ..sim.bootstrap import advance_unlock_terrain
from ..terrain_slots import resolve_terrain_slots
from ..ui.cursor import draw_menu_cursor
from .assets import require_runtime_resources


def menu_ground_camera(state: GameState) -> Vec2:
    camera = state.menu_ground_camera
    if camera is not None:
        return camera
    return Vec2()


def ensure_menu_ground(state: GameState, *, regenerate: bool = False) -> GroundRenderer:
    resources = require_runtime_resources(state)
    ground = state.menu_ground
    generated_new_terrain = ground is None or bool(regenerate)

    if generated_new_terrain:
        terrain = advance_unlock_terrain(
            state.rng,
            unlock_index=int(state.status.quest_unlock_index),
            width=1024,
            height=1024,
        )
        base, overlay, detail = resolve_terrain_slots(terrain.terrain_slots, resources.texture)
    else:
        assert ground is not None
        base = ground.texture
        overlay = ground.overlay
        detail = ground.overlay_detail

    if ground is None:
        ground = GroundRenderer(
            texture=base,
            overlay=overlay,
            overlay_detail=detail,
            width=1024,
            height=1024,
            texture_scale=state.config.display.texture_scale,
        )
        state.menu_ground = ground
    else:
        ground.texture = base
        ground.overlay = overlay
        ground.overlay_detail = detail
    if generated_new_terrain:
        assert ground is not None
        ground.schedule_generate(seed=terrain.terrain_seed, generation_kind="unlock_random")
        state.menu_ground_camera = None
    return ground


def draw_screen_cursor(*, resources: RuntimeResources, pulse_time: float) -> None:
    particles = resources.texture(TextureId.PARTICLES)
    cursor_tex = resources.texture(TextureId.UI_CURSOR)

    mouse = rl.get_mouse_position()
    draw_menu_cursor(particles, cursor_tex, pos=Vec2.from_xy(mouse), pulse_time=float(pulse_time))


def draw_screen_background(state: GameState, ground: GroundRenderer | None, *, entity_alpha: float = 1.0) -> None:
    rl.clear_background(rl.BLACK)
    background = state.pause_background
    if background is not None:
        background.draw_pause_background(entity_alpha=entity_alpha)
    elif ground is not None:
        ground.draw(menu_ground_camera(state))
