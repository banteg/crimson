from __future__ import annotations

from typing import Any, cast

import crimson.render.world.projectiles as world_projectiles
from crimson.projectiles.types import ProjectileTemplateId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world.context import WorldRenderCtx, draw_bullet_trail_quad
from crimson.render.world.viewport import view_transform
from grim.assets import TextureId
from grim.geom import Vec2


class _TextureStub:
    id = 1


class _RuntimeResourcesStub:
    def texture(self, texture_id: TextureId) -> _TextureStub:
        assert texture_id == TextureId.BULLET_TRAIL
        return _TextureStub()


class _WorldStub:
    def __init__(self) -> None:
        self.resources = _RuntimeResourcesStub()

    def build_render_frame(self) -> RenderFrame:
        return RenderFrame(
            world_size=1024.0,
            demo_mode_active=False,
            config=None,
            camera=Vec2(),
            ground=None,
            state=cast(Any, object()),
            players=[],
            creatures=cast(Any, object()),
            resources=cast(Any, self.resources),
            elapsed_ms=0.0,
            bonus_anim_phase=0.0,
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
    frame = world.build_render_frame()
    render_ctx = WorldRenderCtx(
        frame=frame,
        view=view_transform(
            world_size=frame.world_size, config=frame.config, camera=frame.camera, out_size=Vec2(1024, 1024),
        ),
    )

    drawn = draw_bullet_trail_quad(
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
