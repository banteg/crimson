from __future__ import annotations

from pathlib import Path

import crimson.render.world.projectiles as world_projectiles
from crimson.projectiles.types import ProjectileTemplateId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import WorldRenderer
from crimson.render.world.context import build_world_render_ctx
from crimson.render.world.projectiles import draw_bullet_trail
from grim.geom import Vec2


class _TextureStub:
    id = 1


class _RenderResourcesStub:
    def __init__(self) -> None:
        self.bullet_trail_texture = _TextureStub()


class _WorldStub:
    def __init__(self) -> None:
        self.render_resources = _RenderResourcesStub()

    def build_render_frame(self) -> RenderFrame:
        return RenderFrame(
            assets_dir=Path("."),
            world_size=1024.0,
            demo_mode_active=False,
            config=None,
            camera=Vec2(),
            ground=None,
            state=object(),  # type: ignore[arg-type]
            players=[],
            creatures=object(),  # type: ignore[arg-type]
            creature_textures={},
            projs_texture=None,
            particles_texture=None,
            bullet_texture=None,
            bullet_trail_texture=self.render_resources.bullet_trail_texture,  # type: ignore[arg-type]
            arrow_texture=None,
            bonuses_texture=None,
            bodyset_texture=None,
            clock_table_texture=None,
            clock_pointer_texture=None,
            aim_texture=None,
            muzzle_flash_texture=None,
            wicons_texture=None,
            elapsed_ms=0.0,
            bonus_anim_phase=0.0,
            lan_player_rings_enabled=False,
            lan_local_aim_indicators_only=False,
            lan_local_player_slot_index=0,
            rtx_mode=RtxRenderMode.CLASSIC,
        )


def test_draw_bullet_trail_zero_length_still_counts_as_drawn(mocker) -> None:
    mocker.patch.object(world_projectiles.rl, "begin_blend_mode")
    mocker.patch.object(world_projectiles.rl, "rl_set_texture")
    mocker.patch.object(world_projectiles.rl, "rl_begin")
    mocker.patch.object(world_projectiles.rl, "rl_color4ub")
    mocker.patch.object(world_projectiles.rl, "rl_tex_coord2f")
    vertex_mock = mocker.patch.object(world_projectiles.rl, "rl_vertex2f")
    mocker.patch.object(world_projectiles.rl, "rl_end")
    mocker.patch.object(world_projectiles.rl, "end_blend_mode")

    world = _WorldStub()
    renderer = WorldRenderer(world.build_render_frame)
    render_ctx = build_world_render_ctx(renderer)

    drawn = draw_bullet_trail(
        render_ctx,
        Vec2(120.0, 90.0),
        Vec2(120.0, 90.0),
        type_id=int(ProjectileTemplateId.PISTOL),
        alpha=128,
        scale=1.0,
        angle=0.0,
    )

    assert drawn is True
    vertices = [(float(call.args[0]), float(call.args[1])) for call in vertex_mock.call_args_list]
    assert len(vertices) == 4
