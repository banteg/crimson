"""Atmosphere forces are bounded presentation data, never native simulation state."""
from __future__ import annotations

import pickle

import pytest

from crimson.effects import EffectPool, SpriteEffectPool
from crimson.projectiles.types import SecondaryProjectileTypeId
from crimson.sim.batch_apply import apply_presentation_plans
from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.sim.smoke_events import AtmosphereImpulse
from crimson.weapon_runtime.assign import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.builders.session import make_session
from tests.support.factories import make_creature_state, make_step_runtime, place_creatures, player_input
from tests.support.state_digest import session_digest


@pytest.mark.parametrize("weapon", [WeaponId.PISTOL, WeaponId.ION_CANNON, WeaponId.ROCKET_LAUNCHER])
def test_actual_shots_capture_swept_wakes_without_native_or_rng_changes(weapon):
    captured, world = make_session(seed=71, perk_progression_enabled=False)
    plain, plain_world = make_session(seed=71, perk_progression_enabled=False)
    for sim in (world, plain_world):
        weapon_assign_player(sim.players[0], weapon, state=sim.state)
        sim.state.rng = RecordingCrand(sim.state.rng)
    impulses, smoke = [], []
    for tick in range(12):
        inputs = [player_input(aim=Vec2(1000, 512), fire_down=tick == 0)]
        output = captured.step_tick(dt=1/60, inputs=inputs)
        plain._step_tick(dt=1/60, inputs=inputs, commands=None, smoke_emissions=[], atmosphere_impulses=[])
        impulses.extend(output.presentation.atmosphere_impulses)
        smoke.extend(output.presentation.smoke_emissions)
    assert session_digest(captured) == session_digest(plain)
    assert isinstance(world.state.rng, RecordingCrand)
    assert isinstance(plain_world.state.rng, RecordingCrand)
    assert world.state.rng.records == plain_world.state.rng.records
    wakes = [event for event in impulses if event.kind == "wake"]
    assert wakes and all((event.end-event.start).length() > 0 for event in wakes)
    expected_strength = {WeaponId.PISTOL: 3., WeaponId.ION_CANNON: 7., WeaponId.ROCKET_LAUNCHER: 10.}[weapon]
    assert all(event.strength == pytest.approx(expected_strength) for event in wakes)
    if weapon == WeaponId.ROCKET_LAUNCHER:
        rocket = [event for event in smoke if event.profile == "rocket"]
        travel = (wakes[0].end-wakes[0].start).normalized()
        assert rocket and all((event.vel.x*travel.x+event.vel.y*travel.y) < 0 for event in rocket)
        assert all((event.flow_dir.x*travel.x+event.flow_dir.y*travel.y) < 0 for event in rocket)
    else:
        muzzle = [event for event in smoke if event.profile == "muzzle"]
        if weapon == WeaponId.PISTOL:
            assert muzzle
        if muzzle:
            assert all((event.vel.x*event.flow_dir.x+event.vel.y*event.flow_dir.y) > 0 for event in muzzle)
            assert any(event.kind == "muzzle" for event in impulses)


def test_blast_force_does_not_depend_on_puff_detail_or_emitter_light():
    pool = EffectPool()
    impulses = []
    with pool.capture_emissions(impulses=impulses) as smoke:
        pool.spawn_explosion_burst(pos=Vec2(400, 300), scale=2., rng=Crand(5),
                                   detail_preset=1, preserve_bugs=False, emit_light=False)
    assert not smoke
    assert len(impulses) == 1
    blast = impulses[0]
    assert blast.kind == "blast" and blast.start == blast.end == Vec2(400, 300)
    assert blast.strength == 160. and blast.expansion_speed == 360.


def test_wake_budget_cannot_starve_blast_or_muzzle_and_capture_does_not_persist():
    pool = SpriteEffectPool()
    before = pickle.dumps(pool)
    impulses = []
    with pool.capture_emissions(impulses=impulses):
        for _ in range(1000):
            pool.atmosphere_impulse(start=Vec2(), end=Vec2(10, 0), radius=4., strength=1.)
        for kind in ("muzzle", "blast"):
            pool.atmosphere_impulse(start=Vec2(), end=Vec2(10, 0), radius=4., strength=1., kind=kind)
        restored = pickle.loads(pickle.dumps(pool))
        assert restored._smoke_capture().impulses is None
    assert len(impulses) == 194
    assert [event.kind for event in impulses[-2:]] == ["muzzle", "blast"]
    assert pickle.dumps(pool) == before
    pool.atmosphere_impulse(start=Vec2(), end=Vec2(10, 0), radius=4., strength=1.)
    assert len(impulses) == 194


def test_atmosphere_batches_preserve_tick_order_including_empty_ticks(mocker):
    impulse = AtmosphereImpulse(Vec2(1, 2), Vec2(3, 4), 5., 6.)
    plans = [DeterministicPresentationPlan(dt_sim=.01, atmosphere_impulses=(impulse,)),
             DeterministicPresentationPlan(dt_sim=.02)]
    runtime = mocker.MagicMock()
    runtime.presentation.elapsed_ms = 30.
    apply_presentation_plans(plans=plans, runtime=runtime)
    assert runtime.render_resources.consume_smoke_batch.call_args_list == [
        mocker.call((), dt_sim=.01, impulses=(impulse,)), mocker.call((), dt_sim=.02, impulses=()),
    ]


@pytest.mark.parametrize("rocket_type", [SecondaryProjectileTypeId.ROCKET,
    SecondaryProjectileTypeId.HOMING_ROCKET, SecondaryProjectileTypeId.ROCKET_MINIGUN])
def test_every_rocket_ttl_transition_emits_exactly_one_blast(rocket_type):
    session, world = make_session(seed=5, perk_progression_enabled=False)
    entry = world.state.secondary_projectiles.entries[0]
    entry.active, entry.type_id = True, rocket_type
    entry.pos, entry.vel, entry.life_timer = Vec2(400, 300), Vec2(100, 0), 0.
    first = session.step_tick(dt=1/60, inputs=[player_input()])
    second = session.step_tick(dt=1/60, inputs=[player_input()])
    blasts = [event for event in first.presentation.atmosphere_impulses if event.kind == "blast"]
    assert len(blasts) == 1 and blasts[0].strength == 40.
    assert not [event for event in second.presentation.atmosphere_impulses if event.kind == "blast"]


@pytest.mark.parametrize("rocket_type,scale", [(SecondaryProjectileTypeId.ROCKET, 1.),
    (SecondaryProjectileTypeId.HOMING_ROCKET, .35), (SecondaryProjectileTypeId.ROCKET_MINIGUN, .25)])
@pytest.mark.parametrize("ttl", [1., 0.])
def test_rocket_impacts_capture_one_blast_and_tag_outward_smoke(rocket_type, scale, ttl):
    _, world = make_session(seed=9, perk_progression_enabled=False)
    place_creatures(world, [make_creature_state(pos=Vec2(400, 300), hp=10000.)])
    entry = world.state.secondary_projectiles.entries[0]
    entry.active, entry.type_id = True, rocket_type
    entry.pos, entry.vel, entry.life_timer = Vec2(400, 300), Vec2(), ttl
    impulses = []
    with (world.state.effects.capture_emissions(impulses=impulses) as smoke,
          world.state.sprite_effects.capture_emissions(smoke, impulses=impulses)):
        world.state.secondary_projectiles.step(make_step_runtime(world, dt=1/60))
    blasts = [event for event in impulses if event.kind == "blast"]
    assert len(blasts) == 1
    assert blasts[0].strength == pytest.approx(80.*(.5 if ttl == 0 else scale))
    assert len([event for event in smoke if event.profile == "rocket" and event.pos == entry.pos]) == 10
