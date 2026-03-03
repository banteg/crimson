from __future__ import annotations

import crimson.render.world.projectiles as world_projectiles
from crimson.projectiles.types import ProjectileTemplateId
from crimson.render.world import WorldRenderer
from crimson.render.world.context import build_world_render_ctx
from crimson.render.world.projectiles import draw_bullet_trail
from grim.geom import Vec2


class _TextureStub:
    id = 1


class _WorldStub:
    def __init__(self) -> None:
        self.bullet_trail_texture = _TextureStub()


def test_draw_bullet_trail_zero_length_still_counts_as_drawn(mocker) -> None:
    mocker.patch.object(world_projectiles.rl, "begin_blend_mode")
    mocker.patch.object(world_projectiles.rl, "rl_set_texture")
    mocker.patch.object(world_projectiles.rl, "rl_begin")
    mocker.patch.object(world_projectiles.rl, "rl_color4ub")
    mocker.patch.object(world_projectiles.rl, "rl_tex_coord2f")
    vertex_mock = mocker.patch.object(world_projectiles.rl, "rl_vertex2f")
    mocker.patch.object(world_projectiles.rl, "rl_end")
    mocker.patch.object(world_projectiles.rl, "end_blend_mode")

    renderer = WorldRenderer(_world=_WorldStub())  # type: ignore[arg-type]
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
