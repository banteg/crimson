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


def test_draw_creatures_matches_native_overlay_and_species_pass_order(mocker, headless_resources) -> None:
    creatures = [
        make_creature_state(pos=Vec2(10.0, 10.0), type_id=CreatureTypeId.SPIDER_SP2),
        make_creature_state(pos=Vec2(20.0, 20.0), type_id=CreatureTypeId.TROOPER),
        make_creature_state(pos=Vec2(30.0, 30.0), type_id=CreatureTypeId.ZOMBIE),
        make_creature_state(pos=Vec2(40.0, 40.0), type_id=CreatureTypeId.LIZARD),
        make_creature_state(pos=Vec2(50.0, 50.0), type_id=CreatureTypeId.SPIDER_SP1),
        make_creature_state(pos=Vec2(60.0, 60.0), type_id=CreatureTypeId.ALIEN),
        make_creature_state(pos=Vec2(70.0, 70.0), type_id=CreatureTypeId.ZOMBIE, active=False),
    ]
    render_ctx = render_ctx_for_creatures(headless_resources, creatures)
    pos_to_index = {(float(creature.pos.x), float(creature.pos.y)): idx for idx, creature in enumerate(creatures)}
    call_order: list[tuple[str, int]] = []

    def _record_overlay(_render_ctx, creature, **_kwargs) -> None:
        key = (float(creature.pos.x), float(creature.pos.y))
        call_order.append(("overlay", pos_to_index[key]))

    def _record_sprite(*_args, **kwargs) -> None:
        pos = kwargs["pos"]
        key = (float(pos.x), float(pos.y))
        call_order.append(("shadow" if not kwargs.get("body", True) else "sprite", pos_to_index[key]))

    mocker.patch.object(world_draw, "draw_creature_overlays", side_effect=_record_overlay)
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
        ("shadow", 2),
        ("sprite", 2),
        ("shadow", 4),
        ("sprite", 4),
        ("shadow", 0),
        ("sprite", 0),
        ("shadow", 5),
        ("sprite", 5),
        ("shadow", 3),
        ("sprite", 3),
    ]


def test_draw_world_requires_initialized_ground(mocker, headless_resources) -> None:
    render_ctx = render_ctx_for_creatures(headless_resources, [])
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
def test_draw_creatures_uses_native_lifecycle_and_rounding_frames(
    mocker, headless_resources, lifecycle, phase, flags, frame,
) -> None:
    creature = make_creature_state(pos=Vec2(137.0, 241.0), type_id=CreatureTypeId.SPIDER_SP1)
    creature.lifecycle_stage = lifecycle
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

    path = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/creature-hit-flash.json"
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
                lifecycle_stage=row["lifecycle_stage"],
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


@pytest.mark.parametrize("violence_disabled", [0, 1])
def test_creature_flash_follows_each_species_body_batch(mocker, headless_resources, violence_disabled) -> None:
    creatures = [
        make_creature_state(pos=Vec2(10.0, 10.0), type_id=CreatureTypeId.SPIDER_SP1),
        make_creature_state(pos=Vec2(20.0, 20.0), type_id=CreatureTypeId.ZOMBIE),
        make_creature_state(pos=Vec2(30.0, 30.0), type_id=CreatureTypeId.ZOMBIE),
    ]
    for creature in creatures:
        creature.hit_flash_timer = 0.2
    config = default_crimson_cfg()
    config.display.violence_disabled = violence_disabled
    render_ctx = render_ctx_for_creatures(headless_resources, creatures)
    render_ctx = msgspec.structs.replace(render_ctx, frame=msgspec.structs.replace(render_ctx.frame, config=config))
    mocker.patch.object(world_draw.rl, "begin_blend_mode")
    mocker.patch.object(world_draw.rl, "end_blend_mode")
    sprite = mocker.patch.object(world_draw, "draw_creature_sprite")
    world_draw.draw_creatures(render_ctx, ctx=WorldDrawContext())
    calls = [
        (call.kwargs["pos"].x, call.kwargs.get("hit_flash", False))
        for call in sprite.call_args_list
        if call.kwargs.get("body", True)
    ]
    if violence_disabled:
        assert calls == [(20, False), (30, False), (20, True), (30, True), (10, False), (10, True)]
    else:
        assert calls == [(20, False), (30, False), (10, False)]


@pytest.mark.parametrize("entity_alpha", [0.0, 0.0005, 0.001])
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


def test_bonus_render_draws_pickups_under_the_effect_pools(mocker, headless_resources) -> None:
    render_ctx = render_ctx_for_creatures(headless_resources, [])
    order = mocker.Mock()
    for name in (
        "draw_bonus_pickups",
        "draw_bonus_hover_labels",
        "draw_particle_pool",
        "secondary_detonation_pass",
        "draw_sprite_effect_pool",
        "draw_effect_pool",
    ):
        order.attach_mock(mocker.patch.object(world_draw, name), name)

    world_draw.bonus_render(render_ctx, ctx=WorldDrawContext(entity_alpha=1.0))

    assert [call[0] for call in order.mock_calls] == [
        "draw_bonus_pickups",
        "draw_bonus_hover_labels",
        "draw_particle_pool",
        "secondary_detonation_pass",
        "draw_sprite_effect_pool",
        "draw_effect_pool",
    ]
