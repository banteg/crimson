from __future__ import annotations

import msgspec
import numpy as np
import pytest

from crimson.math_parity import f32
from crimson.render.rtx.smoke_simulation import (
    CELL_SIZE,
    MAX_GRID_SIZE,
    MAX_PENDING_EMISSIONS,
    SmokeField,
    SmokeSimulation,
)
from crimson.sim.smoke_events import SmokeEmission
from grim.color import RGBA
from grim.geom import Vec2


def emission(*, slot=0, generation=1, pos=Vec2(512, 512), **changes):
    event = SmokeEmission(slot, generation, pos, Vec2(30, -20), 14., RGBA(1, 1, 1, .37), .7)
    return msgspec.structs.replace(event, **changes)


def test_density_is_advected_and_temperature_cools_without_new_emissions():
    sim = SmokeSimulation()
    sim.consume((emission(),), 0.)
    field = next(iter(sim.fields.values()))
    density, heat = field.density.copy(), float(field.temperature.sum())
    for _ in range(12):
        sim.consume((), 1 / 60)
    assert np.isfinite(field.density).all() and np.isfinite(field.u).all()
    assert field.density.min() >= 0 and field.temperature.min() >= 0
    assert np.max(np.abs(field.density - density)) > .01
    assert float(field.temperature.sum()) < heat
    assert np.max(np.abs(field.u)) > .1


def test_empty_and_fractional_time_do_not_overstep(mocker):
    step = mocker.patch.object(SmokeField, "_step")
    sim = SmokeSimulation()
    sim.consume((), 1.)
    step.assert_not_called()
    sim.consume((emission(),), 0.)
    for _ in range(3):
        sim.consume((), 1 / 240)
    step.assert_not_called()
    sim.consume((), 1 / 240)
    step.assert_called_once_with(1 / 60)
    sim.consume((), 0.)
    assert step.call_count == 1


def test_sequential_tick_batches_have_identical_state():
    a, b = SmokeSimulation(), SmokeSimulation()
    plans = [((emission(),), 1 / 60), ((), 1 / 120), ((), 1 / 120), ((emission(generation=2),), 1 / 60)]
    for emissions, dt in plans:
        a.consume(emissions, dt)
    for emissions, dt in tuple(plans):
        b.consume(emissions, dt)
    np.testing.assert_array_equal(a.fields[0].density, b.fields[0].density)


def test_multiple_trails_share_one_continuous_domain_and_cap_is_bounded():
    sim = SmokeSimulation()
    for slot in range(5):
        sim.consume((emission(slot=slot, pos=Vec2(slot * 160., 0)),), 0.)
    assert len(sim.fields) == 1
    field = sim.fields[0]
    before = float(field.density.sum())
    sim.consume((emission(slot=0, generation=2, pos=Vec2(4000, 0)),), 0.)
    assert float(field.density.sum()) == pytest.approx(before, rel=1e-5)
    assert max(field.density.shape) <= MAX_GRID_SIZE


def test_domain_growth_keeps_world_mass_and_velocity_without_resampling():
    field = SmokeField(Vec2(0, 0), 0)
    field.density[70, 80] = .6
    field.u[70, 80] = 40.
    assert field.include(Vec2(-60, 330), 100.)
    x = int((160 - field.origin.x) / CELL_SIZE)
    y = int((140 - field.origin.y) / CELL_SIZE)
    assert field.density[y, x] == pytest.approx(.6)
    assert field.u[y, x] == 40.
    assert field.density.sum() == pytest.approx(.6)


def test_outward_flow_is_not_reflected_and_does_not_wrap():
    field = SmokeField(Vec2(0, 0), 0)
    field.u.fill(30.)
    field.density[60:80, -8:-2] = 1.
    for _ in range(15):
        field._step(1 / 60)
    assert np.mean(field.u[60:80, -3:]) > 15.
    assert np.max(field.density[:, :20]) == 0.
    assert np.isfinite(field.density).all()


def test_effect_and_sprite_deposits_both_contribute():
    sim = SmokeSimulation()
    sim.consume((emission(),), 0.)
    before = float(sim.fields[0].density.sum())
    sim.consume((emission(source="effect", generation=4),), 0.)
    assert float(sim.fields[0].density.sum()) == pytest.approx(before * 2.)


def test_effect_delay_matches_native_float_age_and_reset_clears_it():
    sim = SmokeSimulation()
    event = emission(source="effect", delay_seconds=f32(.3), expansion=30.)
    sim.consume((event,), 1 / 60)
    assert not sim.fields and len(sim.pending) == 1
    age = -event.delay_seconds
    while age < 0:
        age = f32(f32(age) + f32(1 / 60))
        sim.consume((), 1 / 60)
        assert bool(sim.fields) is (age >= 0)
    sim.consume((msgspec.structs.replace(event, generation=2),), 0.)
    sim.reset()
    assert not sim.fields and not sim.pending


def test_pending_queue_and_oversize_fallback_are_bounded():
    sim = SmokeSimulation()
    delayed = tuple(emission(slot=i, delay_seconds=1.) for i in range(MAX_PENDING_EMISSIONS + 10))
    sim.consume(delayed, 0.)
    assert len(sim.pending) == MAX_PENDING_EMISSIONS
    sim.consume((emission(scale=300.),), 0.)
    assert not sim.fields


def test_idle_fade_and_retirement_do_not_cut_off_continuing_source(mocker):
    mocker.patch.object(SmokeField, "_step")
    sim = SmokeSimulation()
    sim.consume((emission(),), 0.)
    field = sim.fields[0]
    sim.consume((), 9.)
    assert field.fade == pytest.approx(.5)
    sim.consume((emission(generation=2),), .5)
    assert sim.fields[0] is field and field.fade == 1.
    sim.consume((), 8.5)
    assert field.fade == pytest.approx(.5)
    sim.consume((), 1.)
    assert not sim.fields


def test_large_puff_expands_shared_domain_instead_of_starting_another_box():
    sim = SmokeSimulation()
    sim.consume((emission(pos=Vec2(400, 512)),), 0.)
    field = sim.fields[0]
    sim.consume((emission(slot=1, pos=Vec2(490, 512), scale=64., vel=Vec2(), source="effect"),), 0.)
    assert len(sim.fields) == 1 and sim.fields[0] is field
    assert field.size.x > 288


def test_new_deposit_does_not_resurrect_old_fading_density_or_heat():
    field = SmokeField(Vec2(368, 368), 0)
    field.density.fill(.4)
    field.temperature.fill(.2)
    field.idle_seconds = 9.
    # A zero-opacity deposit isolates the lifetime transition from new mass.
    field.inject(emission(color=RGBA(1, 1, 1, 0.), retention_seconds=15.))
    np.testing.assert_allclose(field.density, .2)
    np.testing.assert_allclose(field.temperature, .1)
    assert field.fade == 1. and field.retention_seconds == 15.


def test_dark_general_puff_does_not_become_an_opaque_gray_density_disc():
    sprite, effect = SmokeField(Vec2(368, 368), 0), SmokeField(Vec2(368, 368), 1)
    event = emission(color=RGBA(.1, .1, .1, 1.), scale=64., vel=Vec2())
    sprite.inject(event)
    effect.inject(msgspec.structs.replace(event, source="effect"))
    np.testing.assert_allclose(effect.density, sprite.density * .1, atol=1e-7)
    np.testing.assert_allclose(effect.temperature, sprite.temperature * .1, atol=1e-7)


def test_nuke_source_retains_more_density_than_ordinary_explosion():
    ordinary, nuke = SmokeField(Vec2(368, 368), 0), SmokeField(Vec2(368, 368), 1)
    event = emission(source="effect", color=RGBA(.1, .1, .1, 1.), scale=64., vel=Vec2())
    ordinary.inject(event)
    nuke.inject(msgspec.structs.replace(event, profile="nuke", retention_seconds=15.))
    for _ in range(60):
        ordinary.advance(1 / 60)
        nuke.advance(1 / 60)
    assert float(nuke.density.sum()) > 3. * float(ordinary.density.sum())
    assert nuke.retention_seconds == 15.


def test_nuke_retention_survives_ordinary_deposit_without_restarting_fifteen_seconds(mocker):
    mocker.patch.object(SmokeField, "_step")
    sim = SmokeSimulation()
    sim.consume((emission(retention_seconds=15.),), 0.)
    sim.consume((), 3.)
    sim.consume((emission(generation=2),), 0.)
    assert sim.fields[0].retention_seconds == 12.
    sim.consume((), 11.)
    assert sim.fields[0].fade == pytest.approx(.5)
    sim.consume((), 1.)
    assert not sim.fields


def test_growth_at_width_cap_still_accepts_deposits_and_can_grow_height():
    field = SmokeField(Vec2(0, 0), 0)
    field.include(Vec2(1050, 100), 200)
    field.density.fill(.1)  # No empty margins to reclaim.
    field.include(Vec2(1220, 100), 200)
    assert field.density.shape[1] == MAX_GRID_SIZE
    assert field.include(Vec2(1200, 400), 120)
    assert field.size.y > 500
    assert field.include(Vec2(1200, 100), 120)


def test_empty_margins_are_reclaimed_when_combat_moves():
    field = SmokeField(Vec2(-500, 0), 0)
    field.include(Vec2(600, 100), 100)
    field.density.fill(0)
    x = int((600 - field.origin.x) / CELL_SIZE)
    field.density[60, x] = .7
    assert field.include(Vec2(1300, 100), 100)
    x = int((600 - field.origin.x) / CELL_SIZE)
    assert field.density[60, x] == pytest.approx(.7)
    assert field.origin.x > -500


def test_boundary_scalar_advection_uses_open_first_order_transport():
    field = SmokeField(Vec2(0, 0), 0)
    field.density[:, 1:4] = .8
    u = np.full_like(field.density, 90.)
    v = np.zeros_like(u)
    corrected = field._scalar(field.density, u, v, 1 / 60)
    forward = field._advect(field.density, u, v, 1 / 60)
    np.testing.assert_array_equal(corrected[:, :3], forward[:, :3])
