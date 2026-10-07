from __future__ import annotations

from typing import Any, cast

import pytest
from msgspec import structs

import crimson.render.world.projectiles as world_projectiles
from crimson.creatures.runtime import CreaturePool
from crimson.projectiles.types import Projectile, ProjectileTemplateId, SecondaryProjectile, SecondaryProjectileTypeId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.viewport import view_transform
from crimson.sim.gameplay_state import GameplayState
from grim.assets import TextureId
from grim.geom import Vec2
from tests.support.factories import make_creature_state


class _Texture:
    def __init__(self, texture_id: TextureId) -> None:
        self.id = texture_id
        self.width = 256
        self.height = 256


class _Resources:
    def texture(self, texture_id: TextureId) -> _Texture:
        return _Texture(texture_id)


def _render_ctx(
    *, rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC, creatures: CreaturePool | None = None,
) -> WorldRenderCtx:
    frame = RenderFrame(
        config=None,
        camera=Vec2(),
        ground=None,
        state=GameplayState(),
        players=[],
        creatures=CreaturePool() if creatures is None else creatures,
        resources=cast(Any, _Resources()),
        elapsed_ms=0.0,
        bonus_anim_phase=0.0,
        rtx_mode=rtx_mode,
    )
    return WorldRenderCtx(frame=frame, view=view_transform(config=None, camera=Vec2(), out_size=Vec2(1024, 1024)))


class _Draws:
    """rl calls in order, read back as (kind, payload): sprites with (texture, width),
    immediate-mode vertices and quad-batch ends with the bound texture."""

    def __init__(self, mocker) -> None:
        self.calls = mocker.Mock()
        for name in (
            "begin_blend_mode",
            "end_blend_mode",
            "rl_set_blend_factors_separate",
            "rl_begin",
            "rl_color4ub",
            "rl_tex_coord2f",
        ):
            mocker.patch.object(world_projectiles.rl, name)
        for name in ("rl_set_texture", "rl_vertex2f", "rl_end", "draw_texture_pro"):
            self.calls.attach_mock(mocker.patch.object(world_projectiles.rl, name), name)

    def events(self) -> list[tuple[str, Any]]:
        events: list[tuple[str, Any]] = []
        bound = None
        for name, args, _ in self.calls.mock_calls:
            match name:
                case "rl_set_texture":
                    bound = args[0]
                case "rl_vertex2f":
                    events.append(("vertex", bound))
                case "rl_end":
                    events.append(("quads_end", bound))
                case "draw_texture_pro":
                    events.append(("sprite", (args[0].id, args[2].width)))
        return events


def _passes(events: list[tuple[str, Any]]) -> list[object]:
    """Texture of each run of consecutive draws, in order."""

    textures: list[object] = []
    for kind, payload in events:
        if kind == "quads_end":
            continue
        texture_id = payload[0] if kind == "sprite" else payload
        if not textures or textures[-1] != texture_id:
            textures.append(texture_id)
    return textures


def _place(render_ctx: WorldRenderCtx, projectiles: list[Projectile]) -> None:
    entries = render_ctx.frame.state.projectiles.entries
    for index, projectile in enumerate(projectiles):
        entries[index] = structs.replace(projectile, active=True)


def test_plasma_segment_count_truncates_both_operands_before_dividing() -> None:
    assert world_projectiles.plasma_trail_segment_count(distance=20.9, speed_scale=1.0, divisor=2.5, limit=8) == 8
    assert world_projectiles.plasma_trail_segment_count(distance=11.9, speed_scale=1.55, divisor=2.5, limit=8) == 3
    assert world_projectiles.plasma_trail_segment_count(distance=100.0, speed_scale=0.0, divisor=2.1, limit=3) == 0


def test_projectiles_draw_pass_by_pass_across_the_pool(mocker) -> None:
    # Native draws every trail, then every plasma glow, then every bullet head;
    # the plasma shot in the lower slot must not paint between the pistol's layers.
    draws = _Draws(mocker)
    render_ctx = _render_ctx()
    _place(
        render_ctx,
        [
            Projectile(
                type_id=ProjectileTemplateId.PLASMA_RIFLE, origin=Vec2(100, 100), pos=Vec2(100, 60), life_timer=0.4,
            ),
            Projectile(
                type_id=ProjectileTemplateId.PISTOL,
                origin=Vec2(300, 300),
                pos=Vec2(300, 260),
                vel=Vec2(1, 0),
                life_timer=0.4,
            ),
        ],
    )

    world_projectiles.projectile_render(render_ctx, alpha=1.0)
    events = draws.events()

    assert _passes(events) == [TextureId.BULLET_TRAIL, TextureId.PARTICLES, TextureId.BULLET_I]


def test_plasma_cannon_counts_segments_by_its_wider_divisor(mocker) -> None:
    # 40 units / int(3.5) = 13 tails; the 2.6 step would have given the cap of 18.
    draws = _Draws(mocker)
    render_ctx = _render_ctx()
    _place(
        render_ctx,
        [
            Projectile(
                type_id=ProjectileTemplateId.PLASMA_CANNON,
                origin=Vec2(100, 140),
                pos=Vec2(100, 100),
                life_timer=0.4,
                speed_scale=1.0,
            ),
        ],
    )

    world_projectiles.projectile_render(render_ctx, alpha=1.0)
    events = draws.events()

    tails = [payload for kind, payload in events if kind == "sprite" and payload == (TextureId.PARTICLES, 44.0)]
    assert len(tails) == 13


def test_splitter_gun_draws_its_head_sprite(mocker) -> None:
    draws = _Draws(mocker)
    blend = mocker.patch.object(world_projectiles.rl, "begin_blend_mode")
    render_ctx = _render_ctx()
    _place(
        render_ctx,
        [
            Projectile(
                type_id=ProjectileTemplateId.SPLITTER_GUN,
                origin=Vec2(100, 140),
                pos=Vec2(100, 100),
                vel=Vec2(1, 0),
                life_timer=0.4,
            ),
        ],
    )

    world_projectiles.projectile_render(render_ctx, alpha=1.0)
    events = draws.events()

    assert ("sprite", (TextureId.PROJS, 20.0)) in events
    blend.assert_any_call(world_projectiles.rl.BlendMode.BLEND_ADDITIVE)


def test_ion_chain_draws_each_creature_strips_then_its_glow(mocker) -> None:
    draws = _Draws(mocker)
    pool = CreaturePool()
    pool.entries[1] = make_creature_state(pos=Vec2(140, 100), hp=10.0)
    pool.entries[2] = make_creature_state(pos=Vec2(100, 140), hp=10.0)
    render_ctx = _render_ctx(creatures=pool)
    _place(
        render_ctx,
        [Projectile(type_id=ProjectileTemplateId.ION_RIFLE, origin=Vec2(100, 300), pos=Vec2(100, 100), life_timer=0.2)],
    )

    world_projectiles.projectile_render(render_ctx, alpha=1.0)
    events = draws.events()

    # The streak body stamps the same cell before the chain; start at the first strip.
    first_strip = next(index for index, (kind, _) in enumerate(events) if kind == "quads_end")
    chain = [
        kind if kind != "sprite" else "glow"
        for kind, payload in events[first_strip:]
        if kind == "quads_end"
        or (kind == "sprite" and payload[0] == TextureId.PROJS and payload[1] == pytest.approx(64.0 * 2.2))
    ]
    assert chain == ["quads_end", "glow", "quads_end", "glow"]


def test_secondary_passes_run_over_every_rocket_before_the_next_pass(mocker) -> None:
    draws = _Draws(mocker)
    render_ctx = _render_ctx()
    secondaries = render_ctx.frame.state.secondary_projectiles.entries
    for index in range(2):
        secondaries[index] = SecondaryProjectile(
            active=True,
            type_id=SecondaryProjectileTypeId.ROCKET,
            pos=Vec2(200 + 100 * index, 200),
        )

    world_projectiles.projectile_render(render_ctx, alpha=1.0)
    events = draws.events()

    textures = [payload[0] for kind, payload in events if kind == "sprite"]
    assert textures == [TextureId.PARTICLES] * 2 + [TextureId.PROJS] * 2 + [TextureId.PARTICLES] * 2


@pytest.mark.parametrize("rtx_mode", [RtxRenderMode.CLASSIC, RtxRenderMode.RTX])
def test_streaks_use_the_stamped_rtx_beam_only_in_rtx_mode(mocker, rtx_mode: RtxRenderMode) -> None:
    _Draws(mocker)
    body = mocker.patch.object(world_projectiles, "draw_beam_fast_stamped_body")
    head = mocker.patch.object(world_projectiles, "draw_beam_fast_stamped_head")
    render_ctx = _render_ctx(rtx_mode=rtx_mode)
    _place(
        render_ctx,
        [
            Projectile(
                type_id=ProjectileTemplateId.FIRE_BULLETS, origin=Vec2(100, 300), pos=Vec2(100, 100), life_timer=0.4,
            ),
        ],
    )

    world_projectiles.projectile_render(render_ctx, alpha=1.0)

    expected = 1 if rtx_mode is RtxRenderMode.RTX else 0
    assert body.call_count == head.call_count == expected


@pytest.mark.parametrize("rtx_mode", [RtxRenderMode.CLASSIC, RtxRenderMode.RTX])
@pytest.mark.parametrize(
    "type_id",
    [
        ProjectileTemplateId.ION_RIFLE,
        ProjectileTemplateId.ION_MINIGUN,
        ProjectileTemplateId.ION_CANNON,
        ProjectileTemplateId.FIRE_BULLETS,
    ],
)
@pytest.mark.parametrize("life", [0.4, 0.2])
def test_streak_head_survives_a_zero_length_trail(mocker, rtx_mode, type_id, life) -> None:
    draws = _Draws(mocker)
    mocker.patch.object(world_projectiles, "draw_beam_fast_stamped_body")
    head = mocker.patch.object(world_projectiles, "draw_beam_fast_stamped_head")
    render_ctx = _render_ctx(rtx_mode=rtx_mode)
    _place(render_ctx, [Projectile(type_id=type_id, origin=Vec2(100, 100), pos=Vec2(100, 100), life_timer=life)])
    world_projectiles.projectile_render(render_ctx, alpha=1.0)
    if rtx_mode is RtxRenderMode.RTX:
        head.assert_called_once()
    else:
        sprites = [payload for kind, payload in draws.events() if kind == "sprite" and payload[0] == TextureId.PROJS]
        assert len(sprites) == 1


def test_zero_length_ion_impact_still_chains_to_creatures(mocker) -> None:
    draws = _Draws(mocker)
    pool = CreaturePool()
    pool.entries[1] = make_creature_state(pos=Vec2(140, 100), hp=10.0)
    render_ctx = _render_ctx(creatures=pool)
    _place(
        render_ctx,
        [Projectile(type_id=ProjectileTemplateId.ION_RIFLE, origin=Vec2(100, 100), pos=Vec2(100, 100), life_timer=0.2)],
    )
    world_projectiles.projectile_render(render_ctx, alpha=1.0)
    assert ("quads_end", TextureId.PROJS) in draws.events()
