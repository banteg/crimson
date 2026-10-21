from __future__ import annotations

import msgspec
import numpy as np
import pytest

from crimson.math_parity import f32
from crimson.render.rtx.smoke_simulation import MAX_FIELDS, MAX_PENDING_EMISSIONS, SmokeField, SmokeSimulation
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
    assert a.claims == b.claims
    np.testing.assert_array_equal(a.fields[0].density, b.fields[0].density)


def test_cap_preserves_unclaimed_native_sprites_and_old_generations():
    sim = SmokeSimulation()
    for slot in range(MAX_FIELDS):
        sim.consume((emission(slot=slot, pos=Vec2(slot * 400., 0)),), 0.)
    assert len(sim.fields) == MAX_FIELDS
    sim.consume((emission(slot=0, generation=2, pos=Vec2(4000, 0)),), 0.)
    assert not sim.claims_entry("sprite", 0, 2)
    assert sim.claims_entry("sprite", 0, 1)
    assert not sim.claims_entry("sprite", 63, 1)


def test_effect_and_sprite_claims_do_not_alias():
    sim = SmokeSimulation()
    sim.consume((emission(), emission(source="effect", generation=4)), 0.)
    assert sim.claims_entry("sprite", 0, 1)
    assert sim.claims_entry("effect", 0, 4)
    assert not sim.claims_entry("sprite", 0, 4)


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
    assert sim.claims_entry("effect", 0, 1)
    sim.consume((msgspec.structs.replace(event, generation=2),), 0.)
    sim.reset()
    assert not sim.fields and not sim.claims and not sim.pending


def test_pending_queue_and_oversize_fallback_are_bounded():
    sim = SmokeSimulation()
    delayed = tuple(emission(slot=i, delay_seconds=1.) for i in range(MAX_PENDING_EMISSIONS + 10))
    sim.consume(delayed, 0.)
    assert len(sim.pending) == MAX_PENDING_EMISSIONS
    sim.consume((emission(scale=300.),), 0.)
    assert not sim.fields and not sim.claims


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
    assert not sim.fields and not sim.claims_entry("sprite", 0, 2)


def test_large_puff_gets_new_centered_field_instead_of_clipped_existing_one():
    sim = SmokeSimulation()
    sim.consume((emission(pos=Vec2(400, 512)),), 0.)
    sim.consume((emission(slot=1, pos=Vec2(490, 512), scale=64., vel=Vec2(), source="effect"),), 0.)
    assert len(sim.fields) == 2
    assert sim.fields[1].origin == Vec2(346, 368)


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
