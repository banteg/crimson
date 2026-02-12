from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue
from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_perks_update_effects_pyrokinetic_spawns_particle_burst_when_timer_wraps() -> None:
    dt = 0.2
    state = GameplayState(rng=_FixedRng(0))

    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.PYROKINETIC)] = 1
    player.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.hitbox_size = 16.0
    creature.collision_timer = 0.1

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(state, [player], dt, creatures=[creature], fx_queue=fx_queue)

    assert math.isclose(creature.collision_timer, 0.5, abs_tol=1e-9)
    assert fx_queue.count == 1

    particles = [entry for entry in state.particles.entries if entry.active]
    assert len(particles) == 5
    intensities = [entry.intensity for entry in particles]
    assert all(math.isclose(actual, expected, abs_tol=1e-9) for actual, expected in zip(intensities, (0.8, 0.6, 0.4, 0.3, 0.2)))


def test_perks_update_effects_pyrokinetic_uses_f32_timer_threshold_before_wrapping() -> None:
    # Captured survival run (ticks 4055/4056) sits exactly on the timer boundary;
    # float32 math must avoid wrapping one tick early.
    state = GameplayState(rng=_FixedRng(0))

    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.PYROKINETIC)] = 1
    player.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.hitbox_size = 16.0
    creature.collision_timer = 0.034000009298324585

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(
        state,
        [player],
        0.03400000184774399,
        creatures=[creature],
        fx_queue=fx_queue,
    )
    assert 0.0 < creature.collision_timer < 1e-6
    assert fx_queue.count == 0
    assert all(not entry.active for entry in state.particles.entries)

    perks_update_effects(
        state,
        [player],
        0.03200000151991844,
        creatures=[creature],
        fx_queue=fx_queue,
    )
    assert math.isclose(creature.collision_timer, 0.5, abs_tol=1e-9)
    assert fx_queue.count == 1
    particles = [entry for entry in state.particles.entries if entry.active]
    assert len(particles) == 5
