from __future__ import annotations

import pickle

import msgspec
import pytest

from crimson.bonuses.ids import BonusId
from crimson.effects import EFFECT_POOL_SIZE, SPRITE_EFFECT_POOL_SIZE, EffectPool, SpriteEffectPool
from crimson.effects_atlas import EffectId
from crimson.math_parity import f32
from crimson.sim.batch_apply import apply_presentation_plans
from crimson.sim.commands import PerkPickCommand
from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.sim.sessions import DeterministicSession, IllegalCommandError
from crimson.weapon_runtime.assign import weapon_assign_player
from crimson.weapons import WeaponId
from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.builders.session import make_session
from tests.support.factories import player_input
from tests.support.state_digest import session_digest


def spawn_sprite(pool, rng):
    return pool.spawn(pos=Vec2(11.1, 22.2), vel=Vec2(3.3, 4.4), scale=15.1, color=RGBA(a=0.6), rng=rng)


def test_capture_copies_native_values_and_reused_slots_get_new_identity() -> None:
    pool = SpriteEffectPool()
    rng = Crand(7)
    with pool.capture_emissions() as emissions:
        slot = spawn_sprite(pool, rng)
    event = emissions[0]
    assert (event.slot, event.generation, event.source) == (slot, 1, "sprite")
    assert event.pos == pool.entries[slot].pos
    assert event.pos is not pool.entries[slot].pos
    assert event.scale == f32(15.1)
    assert event.color == pool.entries[slot].color
    original = msgspec.to_builtins(event)
    pool.update(1.0)
    assert spawn_sprite(pool, rng) == slot
    assert pool.generation_for_slot(slot) == 2
    pool.reset()
    assert spawn_sprite(pool, rng) == slot
    assert pool.generation_for_slot(slot) == 3
    assert msgspec.to_builtins(event) == original
    with pytest.raises(AttributeError):
        event.scale = 100  # ty: ignore[invalid-assignment] -- verify runtime immutability too.


def test_capture_preserves_full_pool_allocation_rng_and_native_residue() -> None:
    captured, plain = SpriteEffectPool(), SpriteEffectPool()
    rng_captured, rng_plain = RecordingCrand(Crand(17)), RecordingCrand(Crand(17))
    with captured.capture_emissions() as events:
        for _ in range(SPRITE_EFFECT_POOL_SIZE + 20):
            assert spawn_sprite(captured, rng_captured) == spawn_sprite(plain, rng_plain)
    assert len(events) == SPRITE_EFFECT_POOL_SIZE + 20
    assert rng_captured.records == rng_plain.records
    assert rng_captured.calls == SPRITE_EFFECT_POOL_SIZE + 40
    assert captured.entries == plain.entries
    assert any(event.generation > 1 for event in events)
    assert vars(captured) == vars(plain)


@pytest.mark.parametrize("pool_type", [SpriteEffectPool, EffectPool])
def test_capture_lifetime_and_generations_are_not_pickled(pool_type) -> None:
    pool = pool_type()
    before = pickle.dumps(pool)
    with pytest.raises(RuntimeError, match="abort"), pool.capture_emissions():
        pool._smoke_capture().generations[0] = 19
        # Even a keyframe taken inside a tick contains no active sink.
        restored = pickle.loads(pickle.dumps(pool))
        assert restored.generation_for_slot(0) == 0
        with restored.capture_emissions() as fresh:
            assert fresh == []
        raise RuntimeError("abort")
    with pool.capture_emissions() as fresh:
        assert fresh == []
        with pytest.raises(RuntimeError, match="already active"), pool.capture_emissions():
            pass
    assert pickle.dumps(pool) == before


def test_native_explosion_captures_only_delayed_puffs_with_native_expansion() -> None:
    captured, plain = EffectPool(), EffectPool()
    rng_captured, rng_plain = RecordingCrand(Crand(17)), RecordingCrand(Crand(17))
    with captured.capture_emissions() as events:
        captured.spawn_explosion_burst(pos=Vec2(512, 512), scale=2, rng=rng_captured,
                                       detail_preset=5, preserve_bugs=False)
    plain.spawn_explosion_burst(pos=Vec2(512, 512), scale=2, rng=rng_plain,
                               detail_preset=5, preserve_bugs=False)
    assert len(events) == 2
    assert [event.delay_seconds for event in events] == [0.5, -f32(-0.3)]
    assert all(event.source == "effect" and event.scale == 64.0 for event in events)
    assert all(event.expansion == 320.0 for event in events)
    assert all(event.retention_seconds == 10.0 for event in events)
    assert all(event.profile == "ordinary" for event in events)
    assert all(captured.entries[event.slot].effect_id == EffectId.EXPLOSION_PUFF for event in events)
    assert all(event.color == captured.entries[event.slot].color for event in events)
    assert captured.entries == plain.entries
    assert captured.template == plain.template
    assert rng_captured.records == rng_plain.records


def test_effect_overflow_and_non_smoke_reuse_have_distinct_identities() -> None:
    pool = EffectPool()
    for _ in range(EFFECT_POOL_SIZE - 1):
        pool.spawn(EffectId.BURST, Vec2(), 5, preserve_bugs=False)
    with pool.capture_emissions() as events:
        pool.spawn(EffectId.EXPLOSION_PUFF, Vec2(), 5, preserve_bugs=False)
    assert (events[0].slot, events[0].generation) == (EFFECT_POOL_SIZE, 1)
    pool.update(1.0)
    for _ in range(EFFECT_POOL_SIZE - 1):
        pool.spawn(EffectId.BURST, Vec2(), 5, preserve_bugs=False)
    pool.spawn(EffectId.BURST, Vec2(), 5, preserve_bugs=False)
    assert pool.generation_for_slot(EFFECT_POOL_SIZE) == 2
    assert len(pool.overflow_entries) == 1
    pool.reset()
    for _ in range(EFFECT_POOL_SIZE - 1):
        pool.spawn(EffectId.BURST, Vec2(), 5, preserve_bugs=False)
    with pool.capture_emissions() as events:
        pool.spawn(EffectId.EXPLOSION_PUFF, Vec2(), 5, preserve_bugs=False)
    assert events[0].generation == 3


def test_failed_and_skipped_effect_spawns_emit_nothing() -> None:
    pool = EffectPool()
    with pool.capture_emissions() as events:
        pool.spawn(EffectId.EXPLOSION_PUFF, Vec2(), 2, preserve_bugs=True)
        pool.spawn(EffectId.EXPLOSION_PUFF, Vec2(), 2, preserve_bugs=True)
        for _ in range(EFFECT_POOL_SIZE + 1):
            pool.spawn(EffectId.EXPLOSION_PUFF, Vec2(), 5, preserve_bugs=True)
    assert len(events) == EFFECT_POOL_SIZE - 1


def test_zero_initial_size_keeps_native_delayed_expanding_puff() -> None:
    pool = EffectPool()
    pool.template.scale = 0.0
    with pool.capture_emissions() as events:
        pool.spawn_explosion_burst(
            pos=Vec2(), scale=1.0, rng=Crand(17), detail_preset=5, preserve_bugs=False,
        )
    assert len(events) == 2
    assert all(event.scale == 0.0 and event.expansion == 160.0 for event in events)


def test_actual_nuke_pickup_captures_delayed_smoke_without_gameplay_changes() -> None:
    captured, world = make_session(seed=45, perk_progression_enabled=False)
    plain, plain_world = make_session(seed=45, perk_progression_enabled=False)
    for sim in (world, plain_world):
        sim.state.bonus_pool.spawn_at(sim.players[0].pos, BonusId.NUKE, state=sim.state)
        sim.state.rng = RecordingCrand(sim.state.rng)
    tick = captured.step_tick(dt=1 / 60, inputs=[player_input()])
    plain._step_tick(dt=1 / 60, inputs=[player_input()], commands=None, smoke_emissions=[], atmosphere_impulses=[])
    events = [event for event in tick.presentation.smoke_emissions if event.source == "effect"]
    assert len(events) == 2
    assert [event.delay_seconds for event in events] == [0.5, -f32(-0.3)]
    assert all(event.expansion == 160.0 for event in events)
    assert all(event.retention_seconds == 15.0 for event in events)
    assert all(event.profile == "nuke" for event in events)
    assert len([event for event in tick.presentation.atmosphere_impulses if event.kind == "blast"]) == 1
    assert world.state.bonus_pool.entries[0].picked
    assert session_digest(captured) == session_digest(plain)
    assert isinstance(world.state.rng, RecordingCrand)
    assert isinstance(plain_world.state.rng, RecordingCrand)
    assert world.state.rng.records == plain_world.state.rng.records


def test_session_capture_includes_command_prelude_and_detaches_after_failure(mocker) -> None:
    session, world = make_session()
    session.perk_menu_open = True
    world.state.perk_selection.pending_count = 1
    original = DeterministicSession.apply_command

    def emit_during_command(self, command, *, dt):
        picked = original(self, command, dt=dt)
        spawn_sprite(self.world.state.sprite_effects, self.world.state.rng)
        self.world.state.effects.spawn_explosion_burst(
            pos=Vec2(), scale=1.0, rng=self.world.state.rng, detail_preset=5, preserve_bugs=False,
        )
        return picked

    mocker.patch.object(DeterministicSession, "apply_command", emit_during_command)
    command = PerkPickCommand(player_index=0, choice_index=0)
    tick = session.step_tick(dt=1 / 60, inputs=[player_input()], commands=[command])
    assert [event.source for event in tick.presentation.smoke_emissions[:3]] == ["sprite", "effect", "effect"]
    session.perk_menu_open = True
    with pytest.raises(IllegalCommandError):
        session.step_tick(dt=1 / 60, inputs=[player_input()], commands=[command])
    for pool in (world.state.sprite_effects, world.state.effects):
        with pool.capture_emissions() as fresh:
            assert fresh == []


def test_native_rocket_ticks_preserve_rng_and_complete_session_state() -> None:
    captured, captured_world = make_session(seed=71, perk_progression_enabled=False)
    plain, plain_world = make_session(seed=71, perk_progression_enabled=False)
    for world in (captured_world, plain_world):
        weapon_assign_player(world.players[0], WeaponId.ROCKET_LAUNCHER, state=world.state)
    events = []
    for tick in range(90):
        inputs = [player_input(aim=Vec2(1000, 512), fire_down=tick == 0)]
        output = captured.step_tick(dt=1 / 60, inputs=inputs)
        plain._step_tick(dt=1 / 60, inputs=inputs, commands=None, smoke_emissions=[], atmosphere_impulses=[])
        events.extend(output.presentation.smoke_emissions)
        assert session_digest(captured) == session_digest(plain)
    assert len(events) > 10


@pytest.mark.parametrize("partition", [(1, 1, 1), (3,), (0, 2, 0, 1)])
def test_every_plan_hands_off_smoke_and_dt_in_tick_order(mocker, partition) -> None:
    pool = SpriteEffectPool()
    with pool.capture_emissions() as events:
        spawn_sprite(pool, Crand(7))
    plans = [
        DeterministicPresentationPlan(dt_sim=0.01, smoke_emissions=tuple(events)),
        DeterministicPresentationPlan(dt_sim=0.02),
        DeterministicPresentationPlan(dt_sim=0.03),
    ]
    runtime = mocker.MagicMock()
    runtime.presentation.elapsed_ms = 60
    cursor = 0
    for count in partition:
        apply_presentation_plans(plans=plans[cursor:cursor + count], runtime=runtime)
        cursor += count
    assert runtime.render_resources.consume_smoke_batch.call_args_list == [
        mocker.call(tuple(events), dt_sim=0.01, impulses=()), mocker.call((), dt_sim=0.02, impulses=()),
        mocker.call((), dt_sim=0.03, impulses=()),
    ]
