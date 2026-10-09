from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any, NamedTuple, cast

import pytest
from msgspec import structs

import crimson.render.world.projectiles as world_projectiles
from crimson.perks import PerkId
from crimson.projectiles.types import Projectile, ProjectileTemplateId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.viewport import ViewTransform, view_transform
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.assets import RuntimeResources
from grim.geom import Vec2

_RL_DRAW_CALLS = (
    "begin_blend_mode",
    "end_blend_mode",
    "rl_set_blend_factors_separate",
    "rl_set_texture",
    "rl_begin",
    "rl_end",
    "rl_color4ub",
    "rl_tex_coord2f",
    "rl_vertex2f",
    "draw_texture_pro",
)


def _mock_rl(mocker) -> dict[str, Any]:
    return {name: mocker.patch.object(world_projectiles.rl, name) for name in _RL_DRAW_CALLS}


def _render_projectiles(render_ctx: WorldRenderCtx, projectiles: list[Projectile], *, alpha: float) -> None:
    entries = render_ctx.frame.state.projectiles.entries
    for index, projectile in enumerate(projectiles):
        entries[index] = structs.replace(projectile, active=True)
    world_projectiles.projectile_render(render_ctx, alpha=alpha)


@pytest.fixture
def frame(headless_resources: RuntimeResources) -> RenderFrame:
    return RenderFrame(
        config=None,
        camera=Vec2(),
        ground=None,
        state=GameplayState(),
        players=[],
        creatures=cast(Any, object()),
        resources=headless_resources,
        elapsed_ms=0.0,
        bonus_anim_phase=0.0,
        rtx_mode=RtxRenderMode.CLASSIC,
    )


def _capture_projectile_trail(
    mocker,
    frame: RenderFrame,
    projectile: Projectile,
    *,
    transition_alpha: float = 1.0,
    camera: Vec2 | None = None,
    view_scale: Vec2 | None = None,
):
    rl_calls = _mock_rl(mocker)
    vertices = rl_calls["rl_vertex2f"]
    colors = rl_calls["rl_color4ub"]
    uvs = rl_calls["rl_tex_coord2f"]
    render_ctx = WorldRenderCtx(
        frame=frame,
        view=ViewTransform(
            camera=frame.camera if camera is None else camera,
            view_scale=Vec2(1, 1) if view_scale is None else view_scale,
            screen_size=Vec2(1024, 1024),
            out_size=Vec2(1024, 1024),
        ),
    )
    _render_projectiles(render_ctx, [projectile], alpha=transition_alpha)
    return (
        [tuple(call.args) for call in vertices.call_args_list],
        [tuple(call.args) for call in colors.call_args_list],
        [tuple(call.args) for call in uvs.call_args_list],
    )


class _NativeTrailCase(NamedTuple):
    origin: Vec2
    position: Vec2
    velocity: Vec2
    camera: Vec2
    type_id: ProjectileTemplateId
    words: tuple[int, ...]


def _native_trail_cases() -> list[_NativeTrailCase]:
    path = (
        Path(__file__).resolve().parents[2]
        / "tools/match/evidence/conventional-corner-rounding-2026-09-11/fixtures.jsonl"
    )
    cases = []
    with path.open() as stream:
        for line in stream:
            row = json.loads(line)
            if row["index"] >= 128:
                break
            fixture = row["case"]
            if fixture["fpcw"] != 0x007F:
                continue
            assert fixture["group"] == "discovery" and len(fixture["records"]) == 1
            projectile = fixture["records"][0]
            cases.append(
                _NativeTrailCase(
                    origin=Vec2(*projectile["origin"]),
                    position=Vec2(*projectile["position"]),
                    velocity=Vec2(*projectile["velocity"]),
                    camera=Vec2(*fixture["camera"]),
                    type_id=ProjectileTemplateId(projectile["type_id"]),
                    words=tuple(row["corners"][0]),
                ),
            )
    assert len(cases) == 64
    return cases


@pytest.mark.parametrize("case", _native_trail_cases())
@pytest.mark.parametrize("view_scale", [Vec2(1, 1), Vec2(1.5, 0.75)])
def test_bullet_trail_native_corner_rounding_precedes_viewport_scaling(
    mocker,
    frame: RenderFrame,
    case: _NativeTrailCase,
    view_scale: Vec2,
) -> None:
    projectile = Projectile(
        type_id=case.type_id,
        origin=case.origin,
        pos=case.position,
        vel=case.velocity,
        life_timer=0.2,
    )
    vertices, _, _ = _capture_projectile_trail(
        mocker,
        frame,
        projectile,
        transition_alpha=0.7,
        camera=case.camera,
        view_scale=view_scale,
    )
    assert len(vertices) == 4
    expected = [
        struct.unpack("<I", struct.pack("<f", struct.unpack("<f", struct.pack("<I", word))[0] * scale))[0]
        for word, scale in zip(case.words, (view_scale.x, view_scale.y) * 4, strict=True)
    ]
    actual = [struct.unpack("<I", struct.pack("<f", coordinate))[0] for point in vertices for coordinate in point]
    assert actual == expected


@pytest.mark.parametrize("pos", [Vec2(120, 80), Vec2(120, 90)])
@pytest.mark.parametrize(("velocity", "offset"), [(Vec2(1.2, 0.9), Vec2(1.44, 1.08))])
def test_bullet_trail_width_uses_stored_velocity_even_when_endpoints_disagree(
    mocker,
    frame: RenderFrame,
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
    vertices, _, _ = _capture_projectile_trail(mocker, frame, projectile)
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


@pytest.mark.parametrize("transition_alpha", [1.0, 0.0])
def test_gauss_trail_ignores_transition_alpha(mocker, frame: RenderFrame, transition_alpha: float) -> None:
    # Native 0x42334e reloads clamped life, replacing the earlier life*transition alpha.
    projectile = Projectile(
        type_id=ProjectileTemplateId.GAUSS_GUN,
        origin=Vec2(120, 90),
        pos=Vec2(120, 80),
        vel=Vec2(1.5, 0),
        life_timer=0.5,
    )
    _, colors, _ = _capture_projectile_trail(mocker, frame, projectile, transition_alpha=transition_alpha)
    assert colors == [(127, 127, 127, 0)] * 2 + [(51, 127, 255, 127)] * 2


@pytest.mark.parametrize(("life", "transition", "expected_alpha"), [(0.5, 0.5, 63), (0.5, 0.4, 51), (1.5, 0.5, 127)])
def test_bullet_trail_packs_alpha_after_applying_transition(
    mocker, frame: RenderFrame, life, transition, expected_alpha,
) -> None:
    projectile = Projectile(
        type_id=ProjectileTemplateId.PISTOL,
        origin=Vec2(120, 90),
        pos=Vec2(120, 80),
        vel=Vec2(1.5, 0),
        life_timer=life,
    )
    _, colors, _ = _capture_projectile_trail(mocker, frame, projectile, transition_alpha=transition)
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
def test_plasma_head_alpha_matches_native_draw_boundary(
    mocker, frame: RenderFrame, type_id, head_size, expected_alpha,
) -> None:
    # Native small heads reuse the initial 0.5*transition value at
    # 0x423ac8, 0x423e37, and 0x423fc1; Rifle/Cannon retain 0.45.
    draws = _mock_rl(mocker)["draw_texture_pro"]
    ctx = WorldRenderCtx(
        frame=frame,
        view=view_transform(config=None, camera=Vec2(), out_size=Vec2(1024, 1024)),
    )
    projectile = Projectile(type_id=type_id, origin=Vec2(50, 90), pos=Vec2(110, 210), life_timer=0.4, speed_scale=2.0)
    _render_projectiles(ctx, [projectile], alpha=0.7)
    heads = [call.args for call in draws.call_args_list if call.args[2].width == head_size]
    assert len(heads) == 1
    assert heads[0][-1].a == expected_alpha


@pytest.mark.parametrize(
    ("sharpshooter", "health", "expected_centers"),
    [
        (1, (100.0, 100.0), [100.0, 220.0]),
        (1, (0.0, 100.0), [220.0]),
        (1, (100.0, 0.0), [100.0]),
        (1, (0.0, 0.0), []),
        (0, (100.0, 100.0), []),
    ],
)
def test_sharpshooter_laser_draws_for_each_living_player(
    mocker,
    frame: RenderFrame,
    sharpshooter,
    health,
    expected_centers,
) -> None:
    vertices = _mock_rl(mocker)["rl_vertex2f"]
    players = [
        PlayerState(index=0, pos=Vec2(100.0, 150.0), health=health[0]),
        PlayerState(index=1, pos=Vec2(220.0, 210.0), health=health[1]),
    ]
    state = GameplayState()
    state.perks[int(PerkId.SHARPSHOOTER)] = sharpshooter
    frame = structs.replace(frame, state=state, players=players)
    ctx = WorldRenderCtx(
        frame=frame,
        view=view_transform(config=None, camera=Vec2(), out_size=Vec2(1024, 1024)),
    )
    world_projectiles.projectile_render(ctx, alpha=0.7)
    points = [call.args for call in vertices.call_args_list]
    assert len(points) == 4 * len(expected_centers)
    # With vertical headings, far-end X identifies the player. The near end
    # has the native muzzle-angle offset and need not share the player's X.
    centers = [(points[i + 2][0] + points[i + 3][0]) * 0.5 for i in range(0, len(points), 4)]
    assert centers == pytest.approx(expected_centers)
