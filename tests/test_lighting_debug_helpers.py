from __future__ import annotations

from types import SimpleNamespace

import pytest

from grim.geom import Vec2

from crimson.projectiles import ProjectileTypeId, SecondaryProjectileTypeId
from crimson.weapons import WEAPON_BY_ID
from crimson.views.lighting_debug import (
    EMISSIVE_PROFILES,
    EmissiveProfile,
    LightingDebugView,
    TransientLight,
    collect_shadow_lights,
    collect_shadow_occluders,
    tick_transient_lights,
)


def test_collect_shadow_occluders_filters_invalid_entities_and_clamps_count() -> None:
    player = SimpleNamespace(pos=Vec2(512.0, 512.0), health=100.0, size=48.0)
    creatures = [
        SimpleNamespace(active=False, pos=Vec2(540.0, 512.0), hp=30.0, hitbox_size=16.0, size=40.0),
        SimpleNamespace(active=True, pos=Vec2(560.0, 512.0), hp=30.0, hitbox_size=16.0, size=40.0),
        SimpleNamespace(active=True, pos=Vec2(580.0, 512.0), hp=0.0, hitbox_size=16.0, size=40.0),
        SimpleNamespace(active=True, pos=Vec2(float("nan"), 520.0), hp=30.0, hitbox_size=16.0, size=40.0),
        SimpleNamespace(active=True, pos=Vec2(620.0, 512.0), hp=30.0, hitbox_size=0.0, size=40.0),
        SimpleNamespace(active=True, pos=Vec2(640.0, 512.0), hp=30.0, hitbox_size=16.0, size=40.0),
    ]

    occluders = collect_shadow_occluders(player, creatures, max_occluders=2)

    assert len(occluders) == 2
    assert occluders[0].pos.x == pytest.approx(512.0)
    assert occluders[1].pos.x == pytest.approx(560.0)
    assert occluders[0].radius > 0.0
    assert occluders[1].radius > 0.0


def test_collect_shadow_lights_clamps_count_and_is_deterministic() -> None:
    transients = [
        TransientLight(pos=Vec2(100.0, 100.0), radius=40.0, strength=1.0, ttl=0.4, age=0.0),
        TransientLight(pos=Vec2(110.0, 100.0), radius=40.0, strength=0.8, ttl=0.4, age=0.0),
    ]
    projectiles = [
        SimpleNamespace(active=True, pos=Vec2(200.0, 100.0), type_id=int(ProjectileTypeId.ION_RIFLE)),
        SimpleNamespace(active=True, pos=Vec2(210.0, 100.0), type_id=int(ProjectileTypeId.PLASMA_RIFLE)),
        SimpleNamespace(active=True, pos=Vec2(220.0, 100.0), type_id=0xDEAD),  # ignored, not emissive
    ]
    secondary = [
        SimpleNamespace(active=True, pos=Vec2(300.0, 100.0), type_id=int(SecondaryProjectileTypeId.DETONATION)),
    ]

    lights = collect_shadow_lights(projectiles, secondary, transients, max_lights=4)

    assert len(lights) == 4
    assert [(light.pos.x, light.pos.y) for light in lights] == [
        (100.0, 100.0),
        (110.0, 100.0),
        (200.0, 100.0),
        (210.0, 100.0),
    ]


def test_tick_transient_lights_decays_and_removes_expired_entries() -> None:
    lights = [
        TransientLight(pos=Vec2(50.0, 70.0), radius=60.0, strength=1.0, ttl=0.30, age=0.0),
        TransientLight(pos=Vec2(80.0, 70.0), radius=60.0, strength=0.5, ttl=0.08, age=0.0),
    ]

    step_1 = tick_transient_lights(lights, 0.04)
    assert len(step_1) == 2
    assert step_1[0].age == pytest.approx(0.04)
    assert step_1[1].age == pytest.approx(0.04)

    collected = collect_shadow_lights([], [], step_1, max_lights=4)
    assert len(collected) == 2
    assert collected[0].strength == pytest.approx(1.0 * (1.0 - 0.04 / 0.30))
    assert collected[1].strength == pytest.approx(0.5 * (1.0 - 0.04 / 0.08))

    step_2 = tick_transient_lights(step_1, 0.05)
    assert len(step_2) == 1
    assert step_2[0].pos.x == pytest.approx(50.0)
    assert step_2[0].age == pytest.approx(0.09)


def test_profile_auto_interval_uses_weapon_cooldown_for_all_profiles() -> None:
    for profile in EMISSIVE_PROFILES:
        assert profile.rate_weapon_id is not None
        weapon = WEAPON_BY_ID.get(int(profile.rate_weapon_id))
        assert weapon is not None
        assert weapon.shot_cooldown is not None
        interval = LightingDebugView._profile_auto_interval(profile)
        assert interval == pytest.approx(float(weapon.shot_cooldown))


def test_profile_auto_interval_falls_back_to_profile_interval() -> None:
    profile = EmissiveProfile(name="fallback", auto_interval=0.123, rate_weapon_id=None)

    interval = LightingDebugView._profile_auto_interval(profile)

    assert interval == pytest.approx(0.123)
