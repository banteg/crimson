from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

import crimson.render.world.draw as world_draw_module
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.draw import WorldDrawContext, draw_aim_enhancements, draw_aim_indicators
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


def _make_world(*, players: list[PlayerState]) -> WorldRuntimeHost:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    runtime.reset(player_count=len(players))
    for runtime_player, test_player in zip(runtime.world.players, players, strict=False):
        runtime_player.pos = test_player.pos
        runtime_player.aim = test_player.aim
        runtime_player.spread_heat = test_player.spread_heat
        runtime_player.health = test_player.health
    runtime.render_resources.resources = RuntimeResources(
        assets_dir=runtime.assets_dir,
        textures={TextureId.UI_AIM: rl.Texture()},
        small_font=cast("SmallFontData", object()),
    )
    return runtime


def _draw_ctx() -> WorldDrawContext:
    return WorldDrawContext()


def test_aim_indicators_draw_all_local_players(mocker) -> None:
    world = _make_world(players=_make_players())
    render_ctx = WorldRenderCtx(frame=world.build_render_frame(), view=world.view_transform())
    ctx = _draw_ctx()
    draw_aim_cursor = mocker.patch.object(world_draw_module, "draw_aim_cursor")
    for name in ("begin_blend_mode", "end_blend_mode", "rl_set_texture", "draw_ring"):
        mocker.patch.object(rl, name)
    draw_circle_sector = mocker.patch.object(rl, "draw_circle_sector")

    draw_aim_indicators(render_ctx, ctx=ctx)
    draw_aim_enhancements(render_ctx, ctx=ctx, fade=0.7)

    expected = [render_ctx.view.world_to_screen(player.aim) for player in world.world.players]
    assert [Vec2(call.args[0].x, call.args[0].y) for call in draw_circle_sector.call_args_list] == expected
    assert [call.kwargs["pos"] for call in draw_aim_cursor.call_args_list] == expected
