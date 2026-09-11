from __future__ import annotations

from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, cast

import pytest

import crimson.render.world.draw as world_draw
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.projectiles.types import Projectile, ProjectileTemplateId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.draw import WorldDrawContext
from crimson.render.world.viewport import view_transform
from crimson.sim.gameplay_state import GameplayState
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
        rtx_mode=RtxRenderMode.CLASSIC,
    )
    return WorldRenderCtx(
        frame=frame,
        view=view_transform(
            world_size=frame.world_size,
            config=frame.config,
            camera=frame.camera,
            out_size=Vec2(1024, 1024),
        ),
    )


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
        ctx=WorldDrawContext(entity_alpha=1.0),
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


@pytest.mark.parametrize(
    ("lifecycle", "phase", "flags", "frame"),
    [
        (7.000000476837158, 4.2, CreatureFlags(0), 24),
        (-1.0, 4.2, CreatureFlags.RANGED_ATTACK_SHOCK, 63),
        (20.0, 0.4999999701976776, CreatureFlags(0), 1),
    ],
)
def test_draw_creatures_uses_native_lifecycle_and_rounding_frames(mocker, lifecycle, phase, flags, frame) -> None:
    creature = make_creature_state(pos=Vec2(137.0, 241.0), type_id=CreatureTypeId.SPIDER_SP1)
    creature.lifecycle_stage = lifecycle
    creature.anim_phase = phase
    creature.flags = flags
    render_ctx = _render_ctx_for_creatures([creature])
    mocker.patch.object(world_draw, "_creature_texture", return_value=_TextureStub())
    draw = mocker.patch.object(world_draw.rl, "draw_texture_pro")

    world_draw.draw_creatures(render_ctx, ctx=WorldDrawContext())

    # Both the shadow and body use this frame, without a synthetic phase.
    assert draw.call_count == 2
    for call in draw.call_args_list:
        source = call.args[1]
        assert (source.x, source.y, source.width, source.height) == (
            (frame % 8) * 32,
            (frame // 8) * 32,
            32,
            32,
        )


@pytest.mark.parametrize("entity_alpha", [0.0, 0.0005, 0.001])
def test_draw_world_keeps_gauss_trails_inside_alpha_test_at_zero_transition(mocker, entity_alpha: float) -> None:
    render_ctx = _render_ctx_for_creatures([])
    projectiles = render_ctx.frame.state.projectiles.entries
    projectiles[0] = Projectile(
        active=True,
        type_id=ProjectileTemplateId.GAUSS_GUN,
        origin=Vec2(120, 90),
        pos=Vec2(120, 80),
        vel=Vec2(1.5, 0),
        life_timer=0.3,
    )
    projectiles[1] = Projectile(active=False, type_id=ProjectileTemplateId.GAUSS_GUN, life_timer=0.3)
    projectiles[2] = Projectile(active=True, type_id=ProjectileTemplateId.PISTOL, life_timer=0.3)
    events = []

    @contextmanager
    def alpha_scope():
        events.append("alpha_enter")
        try:
            yield
        finally:
            events.append("alpha_exit")

    resources = cast(Any, render_ctx.frame.resources)
    resources.alpha_test = SimpleNamespace(scope=alpha_scope)
    mocker.patch.object(resources, "texture", return_value=SimpleNamespace(id=1))
    background = mocker.patch.object(world_draw, "draw_background")
    unrelated_passes = [
        mocker.patch.object(world_draw, name)
        for name in (
            "draw_players",
            "draw_creatures",
            "draw_freeze_overlay",
            "draw_projectiles_and_effects",
            "draw_bonus_and_ui",
        )
    ]
    for name in ("begin_blend_mode", "rl_set_texture", "rl_begin", "rl_end", "end_blend_mode", "rl_tex_coord2f"):
        mocker.patch.object(world_draw.rl, name)
    vertices = mocker.patch.object(world_draw.rl, "rl_vertex2f")

    def record_color(*_args):
        assert events[-1] == "alpha_enter"

    colors = mocker.patch.object(world_draw.rl, "rl_color4ub", side_effect=record_color)
    projectile_draw = mocker.spy(world_draw, "draw_projectile")

    world_draw.draw_world(render_ctx, entity_alpha=entity_alpha)

    assert vertices.call_count == 4
    assert [tuple(call.args) for call in colors.call_args_list] == ([(127, 127, 127, 0)] * 2 + [(51, 127, 255, 76)] * 2)
    projectile_draw.assert_called_once_with(render_ctx, projectiles[0], proj_index=0, alpha=entity_alpha)
    background.assert_called_once()
    assert events == ["alpha_enter", "alpha_exit"]
    for draw_pass in unrelated_passes:
        draw_pass.assert_not_called()
