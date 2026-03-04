from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast

import crimson.render.world.draw as world_draw_module
from crimson.render.world import WorldDrawContext, WorldRenderer
from crimson.render.world.context import build_world_render_ctx
from crimson.render.world.draw import draw_aim_enhancements, draw_aim_indicators
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2

if TYPE_CHECKING:
    from crimson.game_world import GameWorld


class _AimRenderResourcesLike(Protocol):
    aim_texture: object


class _AimSimWorldLike(Protocol):
    players: list[PlayerState]


class _AimWorldLike(Protocol):
    sim_world: _AimSimWorldLike
    render_resources: _AimRenderResourcesLike
    lan_player_rings_enabled: bool
    lan_local_aim_indicators_only: bool
    lan_local_player_slot_index: int


@dataclass(slots=True)
class _AimRenderResourcesStub(_AimRenderResourcesLike):
    aim_texture: object = field(default_factory=object)


@dataclass(slots=True)
class _AimSimWorldStub(_AimSimWorldLike):
    players: list[PlayerState]


@dataclass(slots=True)
class _AimWorldStub(_AimWorldLike):
    sim_world: _AimSimWorldLike
    render_resources: _AimRenderResourcesLike = field(default_factory=_AimRenderResourcesStub)
    lan_player_rings_enabled: bool = False
    lan_local_aim_indicators_only: bool = False
    lan_local_player_slot_index: int = 0


def _as_world(world: _AimWorldLike) -> GameWorld:
    return cast("GameWorld", world)


def _make_players() -> list[PlayerState]:
    return [
        PlayerState(index=0, pos=Vec2(0.0, 0.0), aim=Vec2(10.0, 0.0), spread_heat=0.25),
        PlayerState(index=1, pos=Vec2(0.0, 0.0), aim=Vec2(20.0, 0.0), spread_heat=0.25),
        PlayerState(index=2, pos=Vec2(0.0, 0.0), aim=Vec2(30.0, 0.0), spread_heat=0.25),
    ]


def _make_renderer(*, players: list[PlayerState], local_only: bool, local_slot: int) -> WorldRenderer:
    world = _AimWorldStub(
        sim_world=_AimSimWorldStub(players=players),
        lan_player_rings_enabled=False,
        lan_local_aim_indicators_only=bool(local_only),
        lan_local_player_slot_index=int(local_slot),
    )
    return WorldRenderer(_world=_as_world(world))


def _draw_ctx() -> WorldDrawContext:
    return WorldDrawContext()


def _x_from_call_arg(call, *, key: str, arg_index: int) -> float:
    if key in call.kwargs:
        return float(call.kwargs[key].x)
    return float(call.args[arg_index].x)


def test_lan_aim_indicators_draw_local_player_only(mocker) -> None:
    renderer = _make_renderer(players=_make_players(), local_only=True, local_slot=1)
    render_ctx = build_world_render_ctx(renderer)
    ctx = _draw_ctx()
    draw_aim_cursor = mocker.patch.object(world_draw_module, "draw_aim_cursor")
    draw_aim_circle = mocker.Mock()

    draw_aim_indicators(
        render_ctx,
        ctx=ctx,
        world_to_screen_with=lambda pos, _camera, _view_scale: pos,
        draw_aim_circle_fn=draw_aim_circle,
        draw_clock_gauge_fn=lambda _pos, _ms, _scale, _alpha: None,
    )
    draw_aim_enhancements(
        render_ctx,
        ctx=ctx,
        world_to_screen_with=lambda pos, _camera, _view_scale: pos,
    )

    circles = [_x_from_call_arg(call, key="center", arg_index=0) for call in draw_aim_circle.call_args_list]
    cursors = [_x_from_call_arg(call, key="pos", arg_index=-1) for call in draw_aim_cursor.call_args_list]
    assert circles == [20.0]
    assert cursors == [20.0]


def test_non_lan_aim_indicators_draw_all_players(mocker) -> None:
    renderer = _make_renderer(players=_make_players(), local_only=False, local_slot=1)
    render_ctx = build_world_render_ctx(renderer)
    ctx = _draw_ctx()
    draw_aim_cursor = mocker.patch.object(world_draw_module, "draw_aim_cursor")
    draw_aim_circle = mocker.Mock()

    draw_aim_indicators(
        render_ctx,
        ctx=ctx,
        world_to_screen_with=lambda pos, _camera, _view_scale: pos,
        draw_aim_circle_fn=draw_aim_circle,
        draw_clock_gauge_fn=lambda _pos, _ms, _scale, _alpha: None,
    )
    draw_aim_enhancements(
        render_ctx,
        ctx=ctx,
        world_to_screen_with=lambda pos, _camera, _view_scale: pos,
    )

    circles = [_x_from_call_arg(call, key="center", arg_index=0) for call in draw_aim_circle.call_args_list]
    cursors = [_x_from_call_arg(call, key="pos", arg_index=-1) for call in draw_aim_cursor.call_args_list]
    assert circles == [10.0, 20.0, 30.0]
    assert cursors == [10.0, 20.0, 30.0]
