"""Capture original projectile_render (0x422c70) draws through a stub Grim vtable.

The original x86 render routine selects the textures, UVs and sprite geometry;
only graphics submission and D3DX normalization are supplied by this harness.
"""

from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any, cast

import pytest

import crimson.render.world.projectiles as world_projectiles
from crimson.creatures.runtime import CreaturePool
from crimson.game_states import GameStateId
from crimson.projectiles.types import Projectile, ProjectileTemplateId, SecondaryProjectile, SecondaryProjectileTypeId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.viewport import view_transform
from crimson.sim.gameplay_state import GameplayState
from crimson_re.dbg.native_oracle import NativeOracle
from grim.assets import TextureId
from grim.geom import Vec2
from tests.native_oracle._support import (
    PROJECTILE_LAYOUT,
    PROJECTILE_STRIDE,
    SECONDARY_PROJECTILE_LAYOUT,
    SECONDARY_PROJECTILE_STRIDE,
)
from tests.render.test_projectile_render import _Draws


class _NativeDraws:
    def __init__(self, oracle):
        self.oracle = oracle
        self.texture = 0
        self.uv = (0.0, 0.0, 1.0, 1.0)
        self.angle = 0.0
        self.color = (1.0, 1.0, 1.0, 1.0)
        self.quads = []
        slots = [oracle.load_code(b"\xc3" + b"\x90" * 15)] * 256
        pops = {
            0x20: 20,
            0xC4: 8,
            0xE8: 0,
            0xF0: 0,
            0xFC: 4,
            0x100: 16,
            0x104: 8,
            0x10C: 12,
            0x114: 16,
            0x118: 20,
            0x11C: 16,
            0x138: 32,
        }
        for offset, pop in pops.items():
            slots[offset // 4] = oracle.load_code(b"\xc2" + struct.pack("<H", pop) + b"\x90" * 13)

        def hook(offset, fn):
            oracle.stub(slots[offset // 4], fn, pop=pops[offset])

        def bind(c):
            self.texture = c.arg_u32(0)

        def uv(c):
            self.uv = tuple(c.arg_f32(i) for i in range(4))

        def atlas(c):
            grid = c.arg_u32(0)
            frame = c.arg_u32(1)
            self.uv = (
                (frame % grid) / grid,
                (frame // grid) / grid,
                (frame % grid + 1) / grid,
                (frame // grid + 1) / grid,
            )

        def color(c):
            self.color = tuple(c.arg_f32(i) for i in range(4))

        def angle(c):
            self.angle = c.arg_f32(0)

        def quad(c):
            self.quads.append(
                {
                    "texture": self.texture,
                    "uv": self.uv,
                    "xywh": tuple(c.arg_f32(i) for i in range(4)),
                    "rgba": self.color,
                    "angle": self.angle,
                    "caller": hex(c.return_address),
                },
            )

        hook(0xC4, bind)
        hook(0x100, uv)
        hook(0x104, atlas)
        hook(0x114, color)
        hook(0xFC, angle)
        hook(0x11C, quad)
        vtable = oracle.alloc(0x400, data=struct.pack("<256I", *slots))
        oracle.write_u32("grim_interface_ptr", oracle.alloc(0x10, data=struct.pack("<I", vtable)))
        oracle.stub("perk_count_get", 0)

        def normalize(c):
            dst, src = c.arg_u32(0), c.arg_u32(1)
            x, y = oracle.read_f32(src), oracle.read_f32(src + 4)
            length = math.hypot(x, y)
            oracle.write_f32(dst, x / length if length else 0.0)
            oracle.write_f32(dst + 4, y / length if length else 0.0)
            return dst

        oracle.stub("D3DXVec2Normalize", normalize, pop=8)
        for name, handle in [
            ("bullet_trail_texture", 101),
            ("particles_texture", 102),
            ("projectile_texture", 103),
            ("projectile_bullet_texture", 104),
        ]:
            oracle.write_u32(name, handle)
        oracle.write_u8("config_flame_glow_enabled", 1)

    def render(self, projectiles, *, elapsed_ms=0, secondaries=()):
        o = self.oracle
        o.write("projectile_pool", bytes(96 * PROJECTILE_STRIDE))
        o.write("secondary_projectile_pool", bytes(64 * SECONDARY_PROJECTILE_STRIDE))
        o.write_u32("run_elapsed_ms", elapsed_ms)
        o.write_u32("quest_spawn_timeline", elapsed_ms)
        for index, proj in enumerate(projectiles):
            if proj is None:
                continue
            p = o.resolve("projectile_pool") + index * PROJECTILE_STRIDE
            values = {
                "active": int(proj.active),
                "angle": proj.angle,
                "pos_x": proj.pos.x,
                "pos_y": proj.pos.y,
                "origin_x": proj.origin.x,
                "origin_y": proj.origin.y,
                "vel_x": proj.vel.x,
                "vel_y": proj.vel.y,
                "type_id": int(proj.type_id),
                "life_timer": proj.life_timer,
                "speed_scale": proj.speed_scale,
            }
            for name, value in values.items():
                offset, fmt = PROJECTILE_LAYOUT[name]
                o.write(p + offset, struct.pack("<" + fmt, value))
        for index, proj in enumerate(secondaries):
            p = o.resolve("secondary_projectile_pool") + index * SECONDARY_PROJECTILE_STRIDE
            values = {
                "active": int(proj.active),
                "angle": proj.angle,
                "pos_x": proj.pos.x,
                "pos_y": proj.pos.y,
                "vel_x": proj.vel.x,
                "vel_y": proj.vel.y,
                "type_id": int(proj.type_id),
                "life_timer": proj.life_timer,
                "trail_distance": proj.trail_distance,
                "target_id": proj.target_id,
            }
            for name, value in values.items():
                offset, fmt = SECONDARY_PROJECTILE_LAYOUT[name]
                o.write(p + offset, struct.pack("<" + fmt, value))
        self.quads.clear()
        o.call("projectile_render", 1.0)
        return list(self.quads)

    def render_detonations(self, secondaries):
        """`bonus_render` with no players, pickups or particles: only the detonation flashes draw."""
        o = self.oracle
        o.stub("effects_render", 0)
        o.write_f32("ui_transition_alpha", 1.0)
        o.write_u32("game_state_id", GameStateId.GAMEPLAY)
        o.write_u32("game_state_prev", GameStateId.GAMEPLAY)
        o.write_u32("config_player_count", 0)
        o.write("secondary_projectile_pool", bytes(64 * SECONDARY_PROJECTILE_STRIDE))
        for index, proj in enumerate(secondaries):
            p = o.resolve("secondary_projectile_pool") + index * SECONDARY_PROJECTILE_STRIDE
            values = {
                "active": int(proj.active),
                "pos_x": proj.pos.x,
                "pos_y": proj.pos.y,
                "vel_x": proj.detonation_t,
                "vel_y": proj.detonation_scale,
                "type_id": int(proj.type_id),
            }
            for name, value in values.items():
                offset, fmt = SECONDARY_PROJECTILE_LAYOUT[name]
                o.write(p + offset, struct.pack("<" + fmt, value))
        self.quads.clear()
        o.call("bonus_render")
        return list(self.quads)


_NATIVE_HANDLES = {TextureId.PARTICLES: 102, TextureId.PROJS: 103, TextureId.BULLET_I: 104}


class _Texture:
    def __init__(self, texture_id):
        self.id = texture_id
        self.width = self.height = {TextureId.PROJS: 128, TextureId.BULLET_I: 16}.get(texture_id, 256)


class _Resources:
    def texture(self, texture_id):
        return _Texture(texture_id)


@pytest.fixture(scope="module")
def native_draws():
    oracle = NativeOracle(Path(__file__).resolve().parents[2] / "game_bins/crimsonland/1.9.93-gog/crimsonland.exe")
    oracle.run_static_initializers()
    return _NativeDraws(oracle)


def _render_projectiles(ctx):
    world_projectiles.projectile_render(ctx, alpha=1.0)


def _port_draws(
    mocker, projectiles, *, elapsed_ms=0, secondaries=(), textures=(103, 104), render=_render_projectiles, preserve_bugs=True,
):
    draws = _Draws(mocker)
    state = GameplayState(preserve_bugs=preserve_bugs)
    for index, proj in enumerate(projectiles):
        if proj is not None:
            state.projectiles.entries[index] = proj
    for index, proj in enumerate(secondaries):
        state.secondary_projectiles.entries[index] = proj
    frame = RenderFrame(
        config=None,
        camera=Vec2(),
        ground=None,
        state=state,
        players=[],
        creatures=CreaturePool(),
        resources=cast(Any, _Resources()),
        elapsed_ms=elapsed_ms,
        bonus_anim_phase=0,
        rtx_mode=RtxRenderMode.CLASSIC,
    )
    ctx = WorldRenderCtx(frame=frame, view=view_transform(config=None, camera=Vec2(), out_size=Vec2(1024, 1024)))
    render(ctx)
    result = []
    for name, args, _ in draws.calls.mock_calls:
        if name != "draw_texture_pro" or _NATIVE_HANDLES.get(args[0].id) not in textures:
            continue
        texture, src, dst, _origin, angle, _tint = args
        result.append(
            {
                "texture": _NATIVE_HANDLES[texture.id],
                "uv": (
                    src.x / texture.width,
                    src.y / texture.height,
                    (src.x + src.width) / texture.width,
                    (src.y + src.height) / texture.height,
                ),
                "size": dst.width,
                "center": (dst.x, dst.y),
                "angle": angle,
            },
        )
    return result


def _native_sprites(native_draws, projectiles, *, elapsed_ms=0, secondaries=(), textures=(103, 104)):
    return [
        {
            "texture": q["texture"],
            "uv": q["uv"],
            "size": q["xywh"][2],
            "center": (q["xywh"][0] + q["xywh"][2] / 2, q["xywh"][1] + q["xywh"][3] / 2),
            "angle": math.degrees(q["angle"]),
        }
        for q in native_draws.render(projectiles, elapsed_ms=elapsed_ms, secondaries=secondaries)
        if q["texture"] in textures and q["xywh"][2] > 1e-3 and q["rgba"][3] > 1e-3
    ]


@pytest.mark.parametrize("type_id", list(ProjectileTemplateId))
@pytest.mark.parametrize("life", [0.4, 0.2])
@pytest.mark.parametrize("distance", [40.0, 0.0])
def test_primary_projectile_sprite_selection_matches_original(mocker, native_draws, type_id, life, distance):
    # All 19 templates, in flight and fading, with and without a trail. This
    # also locks down the native transparent BULLET_I corner used by Jackhammer.
    projectiles = [
        Projectile(
            active=True,
            type_id=type_id,
            life_timer=life,
            pos=Vec2(100, 100),
            origin=Vec2(100, 100 + distance),
            vel=Vec2(1.5, 0),
        ),
    ]
    native = _native_sprites(native_draws, projectiles)
    port = _port_draws(mocker, projectiles)
    assert len(port) == len(native)
    for actual, expected in zip(port, native, strict=True):
        assert actual["texture"] == expected["texture"]
        assert actual["uv"] == pytest.approx(expected["uv"])
        assert actual["size"] == pytest.approx(expected["size"], abs=1e-4)


@pytest.mark.parametrize(
    "preceding",
    [
        None,
        ProjectileTemplateId.PULSE_GUN,
        ProjectileTemplateId.SPLITTER_GUN,
        ProjectileTemplateId.BLADE_GUN,
        ProjectileTemplateId.ION_RIFLE,
        ProjectileTemplateId.FIRE_BULLETS,
    ],
)
@pytest.mark.parametrize("life", [0.4, 0.2])
@pytest.mark.parametrize("distance", [40.0, 0.0])
@pytest.mark.parametrize("reverse_order", [False, True])
def test_plague_inherits_native_atlas_rotation_and_animation(
    mocker, native_draws, preceding, life, distance, reverse_order,
):
    projectiles = []
    if preceding is not None:
        projectiles.append(
            Projectile(
                active=True,
                type_id=preceding,
                life_timer=life,
                pos=Vec2(300, 100),
                origin=Vec2(300, 100 + distance),
                angle=0.7,
            ),
        )
    projectiles.append(
        Projectile(
            active=True,
            type_id=ProjectileTemplateId.PLAGUE_SPREADER,
            life_timer=life,
            pos=Vec2(100, 100),
            origin=Vec2(100, 100 + distance),
            angle=1.0,
        ),
    )
    if reverse_order:
        projectiles.reverse()
    native = [
        q
        for q in _native_sprites(native_draws, projectiles, elapsed_ms=250)
        if q["texture"] == 103 and q["center"][0] < 200
    ]
    port = [q for q in _port_draws(mocker, projectiles, elapsed_ms=250) if q["texture"] == 103 and q["center"][0] < 200]
    assert len(port) == len(native)
    for actual, expected in zip(port, native, strict=True):
        assert actual["uv"] == pytest.approx(expected["uv"])
        assert actual["size"] == pytest.approx(expected["size"], abs=1e-4)
        assert actual["center"] == pytest.approx(expected["center"], abs=1e-4)
        assert actual["angle"] == pytest.approx(expected["angle"], abs=1e-3)


@pytest.mark.parametrize(
    "type_id",
    [
        SecondaryProjectileTypeId.ROCKET,
        SecondaryProjectileTypeId.HOMING_ROCKET,
        SecondaryProjectileTypeId.DETONATION,
        SecondaryProjectileTypeId.ROCKET_MINIGUN,
    ],
)
@pytest.mark.parametrize("life", [0.0, 0.2])
def test_secondary_projectile_heads_match_original(mocker, native_draws, type_id, life):
    secondaries = [SecondaryProjectile(active=True, type_id=type_id, life_timer=life, pos=Vec2(100, 100), angle=0.7)]
    native = _native_sprites(native_draws, [], secondaries=secondaries)
    port = _port_draws(mocker, [], secondaries=secondaries)
    assert len(port) == len(native)
    for actual, expected in zip(port, native, strict=True):
        assert actual["texture"] == expected["texture"]
        assert actual["uv"] == pytest.approx(expected["uv"])
        assert actual["size"] == pytest.approx(expected["size"], abs=1e-4)
        assert actual["center"] == pytest.approx(expected["center"], abs=1e-4)
        assert actual["angle"] == pytest.approx(expected["angle"], abs=1e-4)


@pytest.mark.parametrize(
    ("last_type", "last_active", "glows"),
    [
        (None, False, 0),
        (ProjectileTemplateId.PISTOL, True, 0),
        (ProjectileTemplateId.FIRE_BULLETS, True, 4),
        (ProjectileTemplateId.FIRE_BULLETS, False, 3),
    ],
)
def test_fire_bullets_glow_follows_the_last_pool_slot(mocker, native_draws, last_type, last_active, glows):
    # Native tests the type through the pointer left on slot 95, not each shot's:
    # a Fire Bullets shot elsewhere gets no glow, and a spent one in slot 95 lights them all.
    pool: list[Projectile | None] = [
        Projectile(active=True, type_id=type_id, life_timer=0.4, pos=Vec2(100 + 60 * index, 100), angle=0.3)
        for index, type_id in enumerate(
            (ProjectileTemplateId.FIRE_BULLETS, ProjectileTemplateId.PISTOL, ProjectileTemplateId.ION_RIFLE),
        )
    ]
    pool += [None] * (95 - len(pool))
    if last_type is not None:
        pool.append(Projectile(active=last_active, type_id=last_type, life_timer=0.4, pos=Vec2(500, 100), angle=0.3))
    native = _native_sprites(native_draws, pool, textures=(102,))
    port = _port_draws(mocker, pool, textures=(102,))
    assert len(native) == glows
    assert len(port) == len(native)
    for actual, expected in zip(port, native, strict=True):
        assert actual["size"] == pytest.approx(expected["size"], abs=1e-4)
        assert actual["center"] == pytest.approx(expected["center"], abs=1e-4)
        assert actual["angle"] == pytest.approx(expected["angle"], abs=1e-3)


@pytest.mark.parametrize("t", [0.1, 0.5, 0.9])
@pytest.mark.parametrize("scale", [1.0, 2.5])
def test_detonation_flash_stretches_the_whole_particles_atlas(mocker, native_draws, t, scale):
    # `bonus_render` resets the UVs to the whole texture before the flashes, with
    # `particles` still bound from the particle pool.
    secondaries = [
        SecondaryProjectile(
            active=True,
            type_id=SecondaryProjectileTypeId.DETONATION,
            pos=Vec2(200, 150),
            detonation_t=t,
            detonation_scale=scale,
        ),
    ]
    native = [
        {
            "texture": q["texture"],
            "uv": q["uv"],
            "size": q["xywh"][2],
            "center": (q["xywh"][0] + q["xywh"][2] / 2, q["xywh"][1] + q["xywh"][3] / 2),
        }
        for q in native_draws.render_detonations(secondaries)
    ]
    port = _port_draws(mocker, [], secondaries=secondaries, textures=(102,), render=world_projectiles.secondary_detonation_pass)
    assert [q["texture"] for q in native] == [102, 102]
    assert len(port) == len(native)
    for actual, expected in zip(port, native, strict=True):
        assert expected["uv"] == (0.0, 0.0, 1.0, 1.0)
        assert actual["uv"] == pytest.approx(expected["uv"])
        assert actual["size"] == pytest.approx(expected["size"], abs=1e-4)
        assert actual["center"] == pytest.approx(expected["center"], abs=1e-4)


_HEADLESS_IN_REWRITE = {
    ProjectileTemplateId.ION_RIFLE,
    ProjectileTemplateId.ION_MINIGUN,
    ProjectileTemplateId.ION_CANNON,
    ProjectileTemplateId.SHRINKIFIER,
    ProjectileTemplateId.BLADE_GUN,
    ProjectileTemplateId.SPIDER_PLASMA,
    ProjectileTemplateId.PLASMA_CANNON,
    ProjectileTemplateId.SPLITTER_GUN,
    ProjectileTemplateId.PLAGUE_SPREADER,
    ProjectileTemplateId.FIRE_BULLETS,
}


@pytest.mark.parametrize("type_id", list(ProjectileTemplateId))
def test_rewrite_shows_bullet_heads_where_native_hides_them(mocker, native_draws, type_id):
    # Native draws a head quad for all but the plasma pair and Pulse, sampling a
    # transparent corner. The rewrite samples the whole sprite and skips the
    # glowing and sprite shots too.
    projectiles = [
        Projectile(active=True, type_id=type_id, life_timer=0.4, pos=Vec2(100, 100), origin=Vec2(100, 140), angle=0.7),
    ]
    native = [q for q in _native_sprites(native_draws, projectiles) if q["texture"] == 104]
    port = [q for q in _port_draws(mocker, projectiles, preserve_bugs=False) if q["texture"] == 104]
    if type_id in _HEADLESS_IN_REWRITE:
        assert port == []
        return
    assert len(port) == len(native)
    for actual, expected in zip(port, native, strict=True):
        assert actual["uv"] == pytest.approx((0.0, 0.0, 1.0, 1.0))
        assert actual["size"] == pytest.approx(expected["size"], abs=1e-4)
        assert actual["center"] == pytest.approx(expected["center"], abs=1e-4)
        assert actual["angle"] == pytest.approx(expected["angle"], abs=1e-3)


@pytest.mark.parametrize("last_active", [False, True])
def test_rewrite_glows_each_fire_bullets_shot(mocker, native_draws, last_active):
    # The rewrite glows Fire Bullets shots on their own type, with native's size and rotation.
    pool: list[Projectile | None] = [
        Projectile(active=True, type_id=type_id, life_timer=0.4, pos=Vec2(100 + 60 * index, 100), angle=0.3)
        for index, type_id in enumerate(
            (ProjectileTemplateId.FIRE_BULLETS, ProjectileTemplateId.PISTOL, ProjectileTemplateId.ION_RIFLE),
        )
    ]
    pool += [None] * (95 - len(pool))
    pool.append(
        Projectile(active=last_active, type_id=ProjectileTemplateId.FIRE_BULLETS, life_timer=0.4, pos=Vec2(500, 100), angle=0.3),
    )
    native = {q["center"]: q for q in _native_sprites(native_draws, pool, textures=(102,))}
    port = _port_draws(mocker, pool, textures=(102,), preserve_bugs=False)
    expected = [(100.0, 100.0)] + ([(500.0, 100.0)] if last_active else [])
    assert [q["center"] for q in port] == pytest.approx(expected)
    for actual in port:
        reference = native[min(native, key=lambda c: abs(c[0] - actual["center"][0]))]
        assert actual["size"] == pytest.approx(reference["size"], abs=1e-4)
        assert actual["angle"] == pytest.approx(reference["angle"], abs=1e-3)


@pytest.mark.parametrize("t", [0.1, 0.5, 0.9])
def test_rewrite_detonation_flash_draws_the_soft_glow_cell(mocker, native_draws, t):
    # Freeware bound `glow64.tga` here; its atlas copy is 4x4 frame 6 (effect 0x10).
    secondaries = [
        SecondaryProjectile(
            active=True, type_id=SecondaryProjectileTypeId.DETONATION, pos=Vec2(200, 150), detonation_t=t, detonation_scale=1.0,
        ),
    ]
    native = native_draws.render_detonations(secondaries)
    port = _port_draws(
        mocker, [], secondaries=secondaries, textures=(102,), render=world_projectiles.secondary_detonation_pass, preserve_bugs=False,
    )
    assert len(port) == len(native) == 2
    for actual, expected in zip(port, native, strict=True):
        assert actual["uv"][:2] == pytest.approx((0.5, 0.25))
        assert actual["uv"][2:] == pytest.approx((0.75, 0.5), abs=2 / 256)
        assert actual["size"] == pytest.approx(expected["xywh"][2], abs=1e-4)
        assert actual["center"] == pytest.approx(
            (expected["xywh"][0] + expected["xywh"][2] / 2, expected["xywh"][1] + expected["xywh"][3] / 2), abs=1e-4,
        )
