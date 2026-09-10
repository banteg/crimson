from __future__ import annotations

from typing import Any, cast

import pytest
from msgspec import structs

import crimson.render.world.projectiles as world_projectiles
from crimson.perks import PerkId
from crimson.projectiles.types import Projectile, ProjectileTemplateId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world.context import WorldRenderCtx, draw_bullet_trail_quad
from crimson.render.world.viewport import view_transform
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.assets import TextureId
from grim.geom import Vec2


class _TextureStub:
    id = 1


class _RuntimeResourcesStub:
    def texture(self, texture_id: TextureId) -> _TextureStub | None:
        if texture_id == TextureId.BULLET_TRAIL:
            return _TextureStub()
        return None


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
            world_size=frame.world_size,
            config=frame.config,
            camera=frame.camera,
            out_size=Vec2(1024, 1024),
        ),
    )

    drawn = draw_bullet_trail_quad(
        render_ctx,
        Vec2(120.0, 90.0),
        Vec2(120.0, 90.0),
        type_id=int(ProjectileTemplateId.PISTOL),
        alpha=128,
        scale=1.0,
        velocity=Vec2(1.5, 0.0),
    )

    assert drawn is True
    vertices = [(float(call.args[0]), float(call.args[1])) for call in vertex_mock.call_args_list]
    assert len(vertices) == 4


def _capture_projectile_trail(mocker, projectile: Projectile, *, transition_alpha: float = 1.0):
    for name in ("begin_blend_mode", "rl_set_texture", "rl_begin", "rl_end", "end_blend_mode"):
        mocker.patch.object(world_projectiles.rl, name)
    vertices = mocker.patch.object(world_projectiles.rl, "rl_vertex2f")
    colors = mocker.patch.object(world_projectiles.rl, "rl_color4ub")
    uvs = mocker.patch.object(world_projectiles.rl, "rl_tex_coord2f")
    frame = _WorldStub().build_render_frame()
    render_ctx = WorldRenderCtx(
        frame=frame,
        view=view_transform(
            world_size=frame.world_size,
            config=frame.config,
            camera=frame.camera,
            out_size=Vec2(1024, 1024),
        ),
    )
    world_projectiles.draw_projectile(render_ctx, projectile, alpha=transition_alpha)
    return (
        [tuple(call.args) for call in vertices.call_args_list],
        [tuple(call.args) for call in colors.call_args_list],
        [tuple(call.args) for call in uvs.call_args_list],
    )


@pytest.mark.parametrize(
    ("type_id", "half_width"),
    [
        (ProjectileTemplateId.ASSAULT_RIFLE, 1.5),
        (ProjectileTemplateId.PISTOL, 1.8),
        (ProjectileTemplateId.GAUSS_GUN, 1.65),
        (ProjectileTemplateId.SHOTGUN, 1.05),
        (ProjectileTemplateId.SPLITTER_GUN, 1.05),
    ],
)
def test_bullet_trail_native_width_and_endpoint_slots(mocker, type_id, half_width) -> None:
    # Native 0x4230e5..0x42360f uses origin for slots 0/1 and pos for slots 2/3.
    projectile = Projectile(
        type_id=type_id,
        origin=Vec2(120, 90),
        pos=Vec2(120, 80),
        vel=Vec2(1.5, 0),
        life_timer=1.0,
    )
    vertices, colors, uvs = _capture_projectile_trail(mocker, projectile)
    for actual, expected in zip(
        vertices,
        [
            (120 - half_width, 90),
            (120 + half_width, 90),
            (120 + half_width, 80),
            (120 - half_width, 80),
        ],
        strict=True,
    ):
        assert actual == pytest.approx(expected)
    assert colors[:2] == [(127, 127, 127, 0)] * 2
    assert [color[3] for color in colors[2:]] == [255, 255]
    assert uvs == [(0, 0), (1, 0), (1, 0.5), (0, 0.5)]


@pytest.mark.parametrize("pos", [Vec2(120, 80), Vec2(120, 90)])
@pytest.mark.parametrize(("velocity", "offset"), [(Vec2(1.2, 0.9), Vec2(1.44, 1.08)), (Vec2(2, 1), Vec2(2.4, 1.2))])
def test_bullet_trail_width_uses_stored_velocity_even_when_endpoints_disagree(
    mocker,
    pos: Vec2,
    velocity: Vec2,
    offset: Vec2,
) -> None:
    projectile = Projectile(
        type_id=ProjectileTemplateId.PISTOL,
        origin=Vec2(120, 90),
        pos=pos,
        vel=velocity,
        angle=0.0,
        life_timer=1.0,
    )
    vertices, _, _ = _capture_projectile_trail(mocker, projectile)
    for actual, expected in zip(
        vertices,
        [
            (120 - offset.x, 90 - offset.y),
            (120 + offset.x, 90 + offset.y),
            (pos.x + offset.x, pos.y + offset.y),
            (pos.x - offset.x, pos.y - offset.y),
        ],
        strict=True,
    ):
        assert actual == pytest.approx(expected)


@pytest.mark.parametrize("transition_alpha", [1.0, 0.5, 0.0])
def test_gauss_trail_ignores_transition_alpha(mocker, transition_alpha: float) -> None:
    # Native 0x42334e reloads clamped life, replacing the earlier life*transition alpha.
    projectile = Projectile(
        type_id=ProjectileTemplateId.GAUSS_GUN,
        origin=Vec2(120, 90),
        pos=Vec2(120, 80),
        vel=Vec2(1.5, 0),
        life_timer=0.5,
    )
    _, colors, _ = _capture_projectile_trail(mocker, projectile, transition_alpha=transition_alpha)
    assert colors == [(127, 127, 127, 0)] * 2 + [(51, 127, 255, 127)] * 2


@pytest.mark.parametrize(("life", "transition", "expected_alpha"), [(0.5, 0.5, 63), (0.5, 0.4, 51), (1.5, 0.5, 127)])
def test_bullet_trail_packs_alpha_after_applying_transition(mocker, life, transition, expected_alpha) -> None:
    projectile = Projectile(
        type_id=ProjectileTemplateId.PISTOL,
        origin=Vec2(120, 90),
        pos=Vec2(120, 80),
        vel=Vec2(1.5, 0),
        life_timer=life,
    )
    _, colors, _ = _capture_projectile_trail(mocker, projectile, transition_alpha=transition)
    assert colors == [(127, 127, 127, 0)] * 2 + [(127, 127, 127, expected_alpha)] * 2


@pytest.mark.parametrize(
    ("type_id", "head_size", "expected_alpha"),
    [
        (ProjectileTemplateId.PLASMA_MINIGUN, 16.0, 89),
        (ProjectileTemplateId.SPIDER_PLASMA, 16.0, 89),
        (ProjectileTemplateId.SHRINKIFIER, 16.0, 89),
        (ProjectileTemplateId.PLASMA_RIFLE, 56.0, 80),
        (ProjectileTemplateId.PLASMA_CANNON, 84.0, 80),
    ],
)
def test_plasma_head_alpha_matches_native_draw_boundary(mocker, type_id, head_size, expected_alpha) -> None:
    # Native small heads reuse the initial 0.5*transition value at
    # 0x423ac8, 0x423e37, and 0x423fc1; Rifle/Cannon retain 0.45.
    texture = mocker.Mock(id=1, width=256, height=256)
    mocker.patch.object(
        _RuntimeResourcesStub,
        "texture",
        side_effect=lambda texture_id: texture if texture_id == TextureId.PARTICLES else None,
    )
    mocker.patch.object(world_projectiles.rl, "begin_blend_mode")
    mocker.patch.object(world_projectiles.rl, "end_blend_mode")
    draws = mocker.patch.object(world_projectiles.rl, "draw_texture_pro")
    frame = _WorldStub().build_render_frame()
    ctx = WorldRenderCtx(
        frame=frame,
        view=view_transform(world_size=frame.world_size, config=None, camera=Vec2(), out_size=Vec2(1024, 1024)),
    )
    projectile = Projectile(type_id=type_id, origin=Vec2(50, 90), pos=Vec2(110, 210), life_timer=0.4, speed_scale=2.0)
    world_projectiles.draw_projectile(ctx, projectile, alpha=0.7)
    heads = [call.args for call in draws.call_args_list if call.args[2].width == head_size]
    assert len(heads) == 1
    assert heads[0][-1].a == expected_alpha


@pytest.mark.parametrize(
    ("preserve_bugs", "perk_counts", "health", "expected_centers"),
    [
        (True, (1, 0), (100.0, 100.0), [100.0, 220.0]),
        (True, (0, 1), (100.0, 100.0), []),
        (False, (1, 0), (100.0, 100.0), [100.0]),
        (False, (0, 1), (100.0, 100.0), [220.0]),
        (True, (1, 0), (0.0, 100.0), [220.0]),
        (False, (1, 0), (0.0, 100.0), []),
        (True, (1, 0), (100.0, 0.0), [100.0]),
        (True, (1, 1), (0.0, 0.0), []),
        (True, (0, 0), (100.0, 100.0), []),
        (False, (1, 1), (100.0, 100.0), [100.0, 220.0]),
    ],
)
def test_sharpshooter_laser_preserves_native_player_zero_owner(
    mocker,
    preserve_bugs,
    perk_counts,
    health,
    expected_centers,
) -> None:
    for name in (
        "begin_blend_mode",
        "rl_set_texture",
        "rl_begin",
        "rl_color4ub",
        "rl_tex_coord2f",
        "rl_end",
        "end_blend_mode",
    ):
        mocker.patch.object(world_projectiles.rl, name)
    vertices = mocker.patch.object(world_projectiles.rl, "rl_vertex2f")
    players = [
        PlayerState(index=0, pos=Vec2(100.0, 150.0), health=health[0]),
        PlayerState(index=1, pos=Vec2(220.0, 210.0), health=health[1]),
    ]
    for player, count in zip(players, perk_counts, strict=True):
        player.perk_counts[int(PerkId.SHARPSHOOTER)] = count
    frame = structs.replace(
        _WorldStub().build_render_frame(),
        state=GameplayState(preserve_bugs=preserve_bugs),
        players=players,
    )
    ctx = WorldRenderCtx(
        frame=frame,
        view=view_transform(world_size=frame.world_size, config=None, camera=Vec2(), out_size=Vec2(1024, 1024)),
    )
    world_projectiles.draw_sharpshooter_laser_sight(
        ctx,
        camera=Vec2(),
        view_scale=Vec2(1.0, 1.0),
        scale=1.0,
        alpha=0.7,
    )
    points = [call.args for call in vertices.call_args_list]
    assert len(points) == 4 * len(expected_centers)
    centers = [(points[i][0] + points[i + 1][0]) * 0.5 for i in range(0, len(points), 4)]
    assert centers == pytest.approx(expected_centers)
