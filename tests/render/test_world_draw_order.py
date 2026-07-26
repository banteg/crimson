from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, cast

import pytest

import crimson.render.world.draw as world_draw
from crimson.creatures.spawn import CreatureTypeId
from crimson.gameplay import GameplayState
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world.context import build_world_render_ctx
from crimson.render.world.draw import WorldDrawContext
from crimson.render.world.renderer import WorldRenderer
from grim.geom import Vec2
from tests.support.factories import make_creature_state


@dataclass(slots=True)
class _TextureStub:
    width: int = 256
    height: int = 256


class _ResourcesStub:
    def texture(self, _texture_id: object) -> _TextureStub:
        return _TextureStub()


def _render_ctx_for_creatures(creatures: Sequence[object]):
    frame = RenderFrame(
        world_size=1024.0,
        demo_mode_active=False,
        config=None,
        camera=Vec2(),
        ground=None,
        state=GameplayState(),
        players=[],
        creatures=cast(Any, SimpleNamespace(entries=creatures)),
        resources=cast(Any, _ResourcesStub()),
        elapsed_ms=0.0,
        bonus_anim_phase=0.0,
        lan_player_rings_enabled=False,
        lan_local_aim_indicators_only=False,
        lan_local_player_slot_index=0,
        rtx_mode=RtxRenderMode.CLASSIC,
    )
    renderer = WorldRenderer(world_size=frame.world_size, config=frame.config, camera=frame.camera)
    return build_world_render_ctx(renderer, render_frame=frame)


def test_draw_creatures_matches_native_overlay_and_species_pass_order(mocker) -> None:
    creatures = [
        make_creature_state(pos=Vec2(10.0, 10.0), type_id=CreatureTypeId.SPIDER_SP2),
        make_creature_state(pos=Vec2(20.0, 20.0), type_id=CreatureTypeId.TROOPER),
        make_creature_state(pos=Vec2(30.0, 30.0), type_id=CreatureTypeId.ZOMBIE),
        make_creature_state(pos=Vec2(40.0, 40.0), type_id=CreatureTypeId.LIZARD),
        make_creature_state(pos=Vec2(50.0, 50.0), type_id=CreatureTypeId.SPIDER_SP1),
        make_creature_state(pos=Vec2(60.0, 60.0), type_id=CreatureTypeId.ALIEN),
        make_creature_state(pos=Vec2(70.0, 70.0), type_id=CreatureTypeId.ZOMBIE, active=False),
    ]
    render_ctx = _render_ctx_for_creatures(creatures)
    pos_to_index = {(float(creature.pos.x), float(creature.pos.y)): idx for idx, creature in enumerate(creatures)}
    call_order: list[tuple[str, int]] = []

    def _record_overlay(_render_ctx, creature, **_kwargs) -> None:
        key = (float(creature.pos.x), float(creature.pos.y))
        call_order.append(("overlay", pos_to_index[key]))

    def _record_sprite(*_args, **kwargs) -> None:
        pos = kwargs["pos"]
        key = (float(pos.x), float(pos.y))
        call_order.append(("sprite", pos_to_index[key]))

    mocker.patch.object(world_draw, "draw_creature_overlays", side_effect=_record_overlay)
    mocker.patch.object(world_draw, "_creature_texture", return_value=_TextureStub())
    mocker.patch.object(world_draw, "draw_creature_sprite", side_effect=_record_sprite)

    world_draw.draw_creatures(
        render_ctx,
        ctx=WorldDrawContext(camera=Vec2(), view_scale=Vec2(1.0, 1.0), scale=1.0, entity_alpha=1.0),
    )

    assert call_order == [
        ("overlay", 0),
        ("overlay", 1),
        ("overlay", 2),
        ("overlay", 3),
        ("overlay", 4),
        ("overlay", 5),
        ("sprite", 2),
        ("sprite", 4),
        ("sprite", 0),
        ("sprite", 5),
        ("sprite", 3),
    ]


def test_draw_world_requires_initialized_ground(mocker) -> None:
    render_ctx = _render_ctx_for_creatures([])
    mocker.patch.object(world_draw.rl, "get_screen_width", return_value=1024)
    mocker.patch.object(world_draw.rl, "get_screen_height", return_value=768)

    with pytest.raises(AssertionError, match="ground renderer must be initialized"):
        world_draw.draw_world(render_ctx)
