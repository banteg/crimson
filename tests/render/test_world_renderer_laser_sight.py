from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any, NamedTuple, cast

import pytest

from crimson.perks import PerkId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import projectiles as world_projectiles
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.viewport import ViewTransform
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.assets import TextureId
from grim.geom import Vec2

EVIDENCE = Path(__file__).resolve().parents[2] / "tools/match/evidence/laser-trig-rounding-2026-09-11"


class _NativeLaserCase(NamedTuple):
    index: int
    case: dict[str, Any]
    corners: list[list[int]]
    colors: list[int]


def _native_cases() -> list[_NativeLaserCase]:
    color_receipt = json.loads((EVIDENCE / "native-colors.json").read_text())
    palettes = {row["alpha"]: row["packed_argb"] for row in color_receipt["cases"] if row["fpcw"] == 0x007F}
    selected = []
    for line in (EVIDENCE / "fixtures.jsonl").read_text().splitlines():
        row = json.loads(line)
        case = row["case"]
        if case["fpcw"] != 0x007F:
            continue
        players = case["players"]
        include = (
            (case["group"] == "discovery" and row["index"] < 32)
            or not row["before_agrees"]
            or (
                case["group"] == "axes-and-cancellation"
                and case["camera"] == [0.0, 0.0]
                and players[0]["position"] == [0.0, 0.0]
            )
            or (
                case["group"] == "gates-and-alpha"
                and case["player_count"] == 2
                and all(p["sharpshooter"] == 1 and p["health"] == 100.0 for p in players)
                and case["glow"] == 0
                and 1e-3 < case["alpha"] <= 1.0
            )
        )
        if include:
            selected.append(_NativeLaserCase(row["index"], case, row["native_corners"], palettes[case["alpha"]]))
    assert len(selected) == 38
    return selected


class _TextureStub:
    id = 1


class _ResourcesStub:
    def texture(self, texture_id: TextureId) -> _TextureStub | None:
        return _TextureStub() if texture_id == TextureId.BULLET_TRAIL else None


@pytest.mark.parametrize("native", _native_cases(), ids=lambda row: str(row.index))
@pytest.mark.parametrize("view_scale", [Vec2(1.0, 1.0), Vec2(2.0, 2.0), Vec2(1.5, 0.75), Vec2(0.25, 0.5)])
def test_sharpshooter_submits_native_vertices_and_colors(mocker, native: _NativeLaserCase, view_scale: Vec2) -> None:
    calls = {}
    for name in (
        "begin_blend_mode",
        "rl_set_texture",
        "rl_begin",
        "rl_color4ub",
        "rl_tex_coord2f",
        "rl_vertex2f",
        "rl_end",
        "end_blend_mode",
    ):
        calls[name] = mocker.patch.object(world_projectiles.rl, name)
    case = native.case
    players = []
    for row in case["players"][: case["player_count"]]:
        player = PlayerState(
            index=row["index"],
            pos=Vec2(*row["position"]),
            health=row["health"],
            aim_heading=row["heading"],
        )
        player.perk_counts[int(PerkId.SHARPSHOOTER)] = row["sharpshooter"]
        players.append(player)
    frame = RenderFrame(
        world_size=1024.0,
        demo_mode_active=False,
        config=None,
        camera=Vec2(),
        ground=None,
        state=GameplayState(preserve_bugs=True),
        players=players,
        creatures=cast("Any", object()),
        resources=cast("Any", _ResourcesStub()),
        elapsed_ms=0.0,
        bonus_anim_phase=0.0,
        rtx_mode=RtxRenderMode.CLASSIC,
    )
    ctx = WorldRenderCtx(
        frame=frame,
        view=ViewTransform(
            camera=Vec2(*case["camera"]),
            view_scale=view_scale,
            screen_size=Vec2(1024.0, 1024.0),
            out_size=Vec2(1024.0, 1024.0).mul_components(view_scale),
        ),
    )
    world_projectiles.draw_sharpshooter_laser_sight(
        ctx,
        camera=ctx.view.camera,
        view_scale=view_scale,
        alpha=case["alpha"],
    )
    actual_words = [
        struct.unpack("<I", struct.pack("<f", value))[0]
        for call in calls["rl_vertex2f"].call_args_list
        for value in call.args
    ]
    expected_words = []
    for quad in native.corners:
        for index, word in enumerate(quad):
            coordinate = struct.unpack("<f", struct.pack("<I", word))[0]
            scale = view_scale.x if index % 2 == 0 else view_scale.y
            expected_words.append(struct.unpack("<I", struct.pack("<f", coordinate * scale))[0])
    assert actual_words == expected_words
    assert [call.args for call in calls["rl_color4ub"].call_args_list] == [
        ((color >> 16) & 255, (color >> 8) & 255, color & 255, (color >> 24) & 255)
        for _ in native.corners
        for color in native.colors
    ]
    assert [call.args for call in calls["rl_tex_coord2f"].call_args_list] == [
        (0.0, 0.0),
        (1.0, 0.0),
        (1.0, 0.5),
        (0.0, 0.5),
    ] * len(native.corners)
    calls["begin_blend_mode"].assert_called_once_with(world_projectiles.rl.BlendMode.BLEND_ADDITIVE)
    assert [call.args for call in calls["rl_set_texture"].call_args_list] == [(1,), (0,)]
    calls["rl_end"].assert_called_once_with()
    calls["end_blend_mode"].assert_called_once_with()
