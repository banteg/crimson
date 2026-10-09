from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import msgspec
import pytest

import crimson.render.world.draw as world_draw
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.projectiles.types import Projectile, ProjectileTemplateId
from crimson.render.world.draw import WorldDrawContext
from grim.config import default_crimson_cfg
from grim.geom import Vec2
from tests.support.creature_draw_capture import render_ctx_for_creatures
from tests.support.factories import make_creature_state


@pytest.mark.parametrize(
    ("lifecycle", "phase", "flags", "frame"),
    [
        (7.000000476837158, 4.2, CreatureFlags(0), 24),
        (-1.0, 4.2, CreatureFlags.RANGED_PLASMA_RIFLE, 63),
        (20.0, 0.4999999701976776, CreatureFlags(0), 1),
    ],
)
def test_draw_creatures_uses_native_lifecycle_and_rounding_frames(
    mocker, headless_resources, lifecycle, phase, flags, frame,
) -> None:
    creature = make_creature_state(pos=Vec2(137.0, 241.0), type_id=CreatureTypeId.SPIDER_SP1)
    creature.death_timer = lifecycle
    creature.anim_phase = phase
    creature.flags = flags
    render_ctx = render_ctx_for_creatures(headless_resources, [creature])
    draw = mocker.patch.object(world_draw.rl, "draw_texture_pro")

    world_draw.draw_creatures(render_ctx, ctx=WorldDrawContext())

    # Both the shadow and body use this frame of the 512px, 8x8 spider atlas, without a synthetic phase.
    assert draw.call_count == 2
    for call in draw.call_args_list:
        source = call.args[1]
        assert (source.x, source.y, source.width, source.height) == (
            (frame % 8) * 64,
            (frame // 8) * 64,
            64,
            64,
        )


def test_creature_hit_flash_draws_match_native_witnesses(mocker, headless_resources) -> None:
    import json
    import struct
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "tests/fixtures/native/creature-hit-flash.json"
    witnesses = json.loads(path.read_text())["render"]
    additive = False
    drawn: list[tuple[object, ...]] = []

    def begin(mode) -> None:
        nonlocal additive
        assert not additive
        assert mode == world_draw.rl.BlendMode.BLEND_ADDITIVE
        additive = True

    def end() -> None:
        nonlocal additive
        assert additive
        additive = False

    def draw(_texture, src, dst, origin, rotation, tint) -> None:
        if additive:
            drawn.append(
                (
                    src.x,
                    src.y,
                    dst.x,
                    dst.y,
                    dst.width,
                    dst.height,
                    origin.x,
                    origin.y,
                    rotation,
                    tint.r,
                    tint.g,
                    tint.b,
                    tint.a,
                ),
            )

    mocker.patch.object(world_draw.rl, "draw_texture_pro", side_effect=draw)
    mocker.patch.object(world_draw.rl, "begin_blend_mode", side_effect=begin)
    mocker.patch.object(world_draw.rl, "end_blend_mode", side_effect=end)
    for witness in witnesses:
        case = witness["input"]
        creatures = []
        for row in case["creatures"]:
            creature = make_creature_state(
                pos=Vec2(row["pos_x"], row["pos_y"]),
                active=bool(row["active"]),
                type_id=CreatureTypeId(row["type_id"]),
                death_timer=row["death_timer"],
                size=row["size"],
                flags=CreatureFlags(row["flags"]),
            )
            creature.anim_phase = row["anim_phase"]
            creature.heading = row["heading"]
            creature.hit_flash_timer = row["hit_flash_timer"]
            creatures.append(creature)
        config = default_crimson_cfg()
        config.display.violence_disabled = case["flash"]
        render_ctx = render_ctx_for_creatures(headless_resources, creatures)
        render_ctx = msgspec.structs.replace(
            render_ctx,
            frame=msgspec.structs.replace(render_ctx.frame, config=config),
            view=msgspec.structs.replace(render_ctx.view, camera=Vec2(13.25, -18.5)),
        )
        drawn.clear()
        ctx = WorldDrawContext(entity_alpha=case["transition"])
        # Compare a species pass, including the native filter for other types.
        # The render_all gate and batch order are exercised separately below.
        if case["flash"]:
            world_draw.draw_creature_hit_flashes(render_ctx, type_id=CreatureTypeId(case["type_id"]), ctx=ctx)
        assert not additive
        assert len(drawn) == len(witness["expected"]) * 2, case["name"]
        for index, expected in enumerate(witness["expected"]):
            first, second = drawn[index * 2 : index * 2 + 2]
            assert first == second
            frame = expected["frame"]
            x, y, width, height = struct.unpack("<4f", struct.pack("<4I", *expected["quad_bits"]))
            rotation = struct.unpack("<f", struct.pack("<I", expected["rotation_bits"]))[0]
            assert first[:8] == (
                (frame % 8) * 64,
                (frame // 8) * 64,
                x + width / 2,
                y + height / 2,
                width,
                height,
                width / 2,
                height / 2,
            ), case["name"]
            assert first[8] == pytest.approx(rotation * world_draw._RAD_TO_DEG, abs=1e-5)
            packed = expected["packed_color"]
            assert first[9:] == (255, 255, 255, packed >> 24), case["name"]


@pytest.mark.parametrize("entity_alpha", [0.0, 0.001])
def test_draw_world_keeps_gauss_trails_inside_alpha_test_at_zero_transition(
    mocker, headless_resources, entity_alpha: float,
) -> None:
    render_ctx = render_ctx_for_creatures(headless_resources, [])
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

    mocker.patch.object(headless_resources, "alpha_test", SimpleNamespace(scope=alpha_scope))
    background = mocker.patch.object(world_draw, "draw_background")
    unrelated_passes = [
        mocker.patch.object(world_draw, name)
        for name in (
            "draw_players",
            "draw_creatures",
            "draw_freeze_overlay",
            "bonus_render",
        )
    ]
    for name in ("begin_blend_mode", "rl_set_texture", "rl_begin", "rl_end", "end_blend_mode", "rl_tex_coord2f"):
        mocker.patch.object(world_draw.rl, name)
    vertices = mocker.patch.object(world_draw.rl, "rl_vertex2f")

    def record_color(*_args):
        assert events[-1] == "alpha_enter"

    colors = mocker.patch.object(world_draw.rl, "rl_color4ub", side_effect=record_color)
    projectile_render = mocker.spy(world_draw, "projectile_render")

    world_draw.draw_world(render_ctx, entity_alpha=entity_alpha)

    assert vertices.call_count == 4
    assert [tuple(call.args) for call in colors.call_args_list] == ([(127, 127, 127, 0)] * 2 + [(51, 127, 255, 76)] * 2)
    projectile_render.assert_called_once_with(render_ctx, alpha=entity_alpha)
    background.assert_called_once()
    assert events == ["alpha_enter", "alpha_exit"]
    for draw_pass in unrelated_passes:
        draw_pass.assert_not_called()
