from __future__ import annotations

from crimson.projectiles import ProjectileTypeId
from crimson.render.world import WorldRenderer
from crimson.render.world.context import build_world_render_ctx
from crimson.render.world.projectiles import draw_bullet_trail
from grim.geom import Vec2


class _TextureStub:
    id = 1


class _WorldStub:
    def __init__(self) -> None:
        self.bullet_trail_texture = _TextureStub()


def test_draw_bullet_trail_zero_length_still_counts_as_drawn(monkeypatch) -> None:
    vertices: list[tuple[float, float]] = []

    monkeypatch.setattr("crimson.render.world.projectiles.rl.begin_blend_mode", lambda _mode: None)
    monkeypatch.setattr("crimson.render.world.projectiles.rl.rl_set_texture", lambda _tex_id: None)
    monkeypatch.setattr("crimson.render.world.projectiles.rl.rl_begin", lambda _mode: None)
    monkeypatch.setattr("crimson.render.world.projectiles.rl.rl_color4ub", lambda _r, _g, _b, _a: None)
    monkeypatch.setattr("crimson.render.world.projectiles.rl.rl_tex_coord2f", lambda _u, _v: None)
    monkeypatch.setattr(
        "crimson.render.world.projectiles.rl.rl_vertex2f",
        lambda x, y: vertices.append((float(x), float(y))),
    )
    monkeypatch.setattr("crimson.render.world.projectiles.rl.rl_end", lambda: None)
    monkeypatch.setattr("crimson.render.world.projectiles.rl.end_blend_mode", lambda: None)

    renderer = WorldRenderer(_world=_WorldStub())  # type: ignore[arg-type]
    render_ctx = build_world_render_ctx(renderer)

    drawn = draw_bullet_trail(
        render_ctx,
        Vec2(120.0, 90.0),
        Vec2(120.0, 90.0),
        type_id=int(ProjectileTypeId.PISTOL),
        alpha=128,
        scale=1.0,
        angle=0.0,
    )

    assert drawn is True
    assert len(vertices) == 4
