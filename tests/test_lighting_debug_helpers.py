from __future__ import annotations

import math
from pathlib import Path
from types import SimpleNamespace

import pytest

from grim.geom import Vec2
from grim.view import ViewContext

from crimson.projectiles import ProjectileTypeId, SecondaryProjectileTypeId
from crimson.weapons import WEAPON_BY_ID
from crimson.views.lighting_debug import (
    EMISSIVE_PROFILES,
    EmissiveProfile,
    LightingDebugView,
    TransientLight,
    _build_static_occluders,
    _profile_light_defaults,
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
        SimpleNamespace(active=True, pos=Vec2(200.0, 100.0), angle=0.0, type_id=int(ProjectileTypeId.PISTOL)),
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


def test_ion_lights_are_head_to_tail_omni_with_weaker_tail() -> None:
    projectiles = [
        SimpleNamespace(
            active=True,
            pos=Vec2(300.0, 100.0),
            origin=Vec2(80.0, 100.0),
            angle=0.0,
            type_id=int(ProjectileTypeId.ION_RIFLE),
        )
    ]

    lights = collect_shadow_lights(projectiles, [], [], max_lights=6)

    assert len(lights) == 3
    assert lights[0].pos.x == pytest.approx(300.0)
    assert lights[1].pos.x < lights[0].pos.x
    assert lights[2].pos.x < lights[1].pos.x
    assert lights[0].strength > lights[1].strength > lights[2].strength
    assert all(light.focus == pytest.approx(0.0) for light in lights)
    assert all(light.stretch == pytest.approx(1.0) for light in lights)
    assert all(light.dir_x == pytest.approx(0.0) for light in lights)
    assert all(light.dir_y == pytest.approx(0.0) for light in lights)


def test_plasma_light_is_omnidirectional() -> None:
    projectiles = [
        SimpleNamespace(
            active=True,
            pos=Vec2(220.0, 100.0),
            origin=Vec2(180.0, 100.0),
            angle=1.2,
            type_id=int(ProjectileTypeId.PLASMA_RIFLE),
        )
    ]

    lights = collect_shadow_lights(projectiles, [], [], max_lights=6)

    assert len(lights) == 1
    assert lights[0].focus == pytest.approx(0.0)
    assert lights[0].stretch == pytest.approx(1.0)
    assert lights[0].dir_x == pytest.approx(0.0)
    assert lights[0].dir_y == pytest.approx(0.0)


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


def test_profile_light_defaults_uses_primary_or_secondary_specs() -> None:
    ion_profile = next(profile for profile in EMISSIVE_PROFILES if profile.name == "Ion Rifle")
    det_profile = next(profile for profile in EMISSIVE_PROFILES if profile.name == "Explosion")

    ion_radius, ion_strength, ion_focus, ion_stretch = _profile_light_defaults(ion_profile)
    det_radius, det_strength, det_focus, det_stretch = _profile_light_defaults(det_profile)

    assert ion_radius > 0.0
    assert ion_strength > 0.0
    assert ion_focus >= 0.0
    assert ion_stretch >= 1.0
    assert det_radius > 0.0
    assert det_strength > 0.0
    assert det_focus >= 0.0
    assert det_stretch >= 1.0


def test_build_static_occluders_produces_finite_positive_circles() -> None:
    occluders = _build_static_occluders()

    assert occluders
    assert all(occ.radius > 0.0 for occ in occluders)
    assert all(math.isfinite(float(occ.pos.x)) for occ in occluders)
    assert all(math.isfinite(float(occ.pos.y)) for occ in occluders)


def test_static_scene_collect_shadow_state_uses_static_occluders_and_emitters() -> None:
    view = LightingDebugView(ViewContext(assets_dir=Path(".") / "artifacts" / "assets"))

    view._set_static_scene_enabled(True)
    view._collect_shadow_state()

    assert view._static_scene_enabled is True
    assert len(view._last_occluders) > 0
    assert len(view._last_lights) > 0


def test_adjust_selected_tune_rt_scale_resets_shadow_rt_size() -> None:
    view = LightingDebugView(ViewContext(assets_dir=Path(".") / "artifacts" / "assets"))
    rt_param_index = 0
    for i in range(32):
        view._tune_param_index = i
        if view._selected_tune_param().key == "rt_scale":
            rt_param_index = i
            break

    view._tune_param_index = int(rt_param_index)
    assert view._selected_tune_param().key == "rt_scale"
    view._shadow_rt_size = (320, 180)
    view._shadow_accum_ready = True
    view._adjust_selected_tune(+1)

    assert view._shadow_rt_size == (0, 0)
    assert view._shadow_accum_ready is False


def test_dump_all_modes_honors_autodiag_frame_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    view = LightingDebugView(ViewContext(assets_dir=Path(".") / "artifacts" / "assets"))
    view._dump_all_modes_enabled = True
    view._dump_mode_sequence = (0, 1, 2, 3)
    view._autodiag_enabled = True
    view._autodiag_total_frames = 30

    monkeypatch.setattr(view, "_reset_scene", lambda: None)
    monkeypatch.setattr(view, "_emit_profile", lambda: None)
    monkeypatch.setattr(view, "_set_tune_value", lambda key, value, **kwargs: None)

    safety = 0
    while not view.close_requested and safety < 200:
        view._run_dump_all_modes()
        safety += 1

    assert view.close_requested is True
    assert view._dump_total_frames == 30
    assert view._dump_total_frame == 30
