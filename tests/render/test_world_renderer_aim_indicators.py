from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

import crimson.render.world.draw as world_draw_module
from crimson.render.world import WorldDrawContext
from crimson.render.world.context import build_world_render_ctx
from crimson.render.world.draw import draw_aim_enhancements, draw_aim_indicators
from crimson.sim.state_types import PlayerState
from grim.assets import RuntimeResources, TextureId
from grim.geom import Vec2
from grim.raylib_api import rl
from tests.support.world_runtime import WorldRuntimeHost

if TYPE_CHECKING:
    from grim.fonts.small import SmallFontData


def _make_players() -> list[PlayerState]:
    return [
        PlayerState(index=0, pos=Vec2(0.0, 0.0), aim=Vec2(10.0, 0.0), spread_heat=0.25),
        PlayerState(index=1, pos=Vec2(0.0, 0.0), aim=Vec2(20.0, 0.0), spread_heat=0.25),
        PlayerState(index=2, pos=Vec2(0.0, 0.0), aim=Vec2(30.0, 0.0), spread_heat=0.25),
    ]


def _make_world(*, players: list[PlayerState], local_only: bool, local_slot: int) -> WorldRuntimeHost:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    world.reset(player_count=len(players))
    for runtime_player, test_player in zip(world.sim_world.players, players, strict=False):
        runtime_player.pos = test_player.pos
        runtime_player.aim = test_player.aim
        runtime_player.spread_heat = test_player.spread_heat
        runtime_player.health = test_player.health
    world.lan_local_aim_indicators_only = bool(local_only)
    world.lan_local_player_slot_index = int(local_slot)
    world.render_resources.resources = RuntimeResources(
        assets_dir=world.assets_dir,
        textures={TextureId.UI_AIM: rl.Texture()},
        small_font=cast("SmallFontData", object()),
    )
    return world


def _draw_ctx() -> WorldDrawContext:
    return WorldDrawContext()


def _x_from_call_arg(call, *, key: str, arg_index: int) -> float:
    if key in call.kwargs:
        return float(call.kwargs[key].x)
    return float(call.args[arg_index].x)


def test_lan_aim_indicators_draw_local_player_only(mocker) -> None:
    world = _make_world(players=_make_players(), local_only=True, local_slot=1)
    renderer = world.renderer
    render_ctx = build_world_render_ctx(renderer, render_frame=world.build_render_frame())
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
    world = _make_world(players=_make_players(), local_only=False, local_slot=1)
    renderer = world.renderer
    render_ctx = build_world_render_ctx(renderer, render_frame=world.build_render_frame())
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
