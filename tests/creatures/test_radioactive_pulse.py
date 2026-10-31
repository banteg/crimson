from __future__ import annotations

import pytest

from crimson.cl_build import ClBuild
from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureTypeId
from crimson.creatures.spawn_ids import CreatureAiMode
from crimson.math_parity import f32, x87_pc24_mul, x87_pc24_sub
from crimson.perks import PerkId
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.builders.session import make_world
from tests.support.factories import step_creatures
from tests.support.helpers import assert_rng_progression

_DT = 0.01
_SEED = 0x1234
# A pulse 80 units from the player deals (100 - 80) * 0.3.
_PULSE_DAMAGE = x87_pc24_mul(20.0, f32(0.3))


def _step_radioactive(cl_build: ClBuild, *, preserve_bugs: bool, creature: CreatureState) -> WorldState:
    world = make_world(preserve_bugs=preserve_bugs)
    world.state.cl_build = cl_build
    world.state.perks[PerkId.RADIOACTIVE] = 1
    world.state.rng = RecordingCrand(Crand(_SEED))
    creature.pos = world.players[0].pos + Vec2(80, 0)
    world.creatures.entries[0] = creature
    step_creatures(world, _DT)
    return world


@pytest.mark.parametrize("preserve_bugs", [False, True])
@pytest.mark.parametrize("cl_build", list(ClBuild))
@pytest.mark.parametrize("exact", [False, True])
def test_radioactive_spares_lizards_only_in_1_9_93(cl_build, preserve_bugs, exact):
    hp = _PULSE_DAMAGE if exact else 1.0
    creature = CreatureState(
        active=True, hp=hp, reward_value=100, move_speed=0, dot_tick_timer=-1, type_id=CreatureTypeId.LIZARD,
    )
    death_timer = creature.death_timer

    world = _step_radioactive(cl_build, preserve_bugs=preserve_bugs, creature=creature)

    # An exact-zero pulse is lethal only under the rules 2 fix (original bug 48).
    lethal = not (exact and preserve_bugs)
    killed = lethal and cl_build == ClBuild.V1_9_8
    assert creature.hp == (1.0 if lethal and not killed else x87_pc24_sub(hp, _PULSE_DAMAGE))
    assert world.players[0].experience == (100 if killed else 0)
    assert creature.death_timer == (x87_pc24_sub(death_timer, _DT) if killed else death_timer)


def _linked_creature() -> CreatureState:
    # Its link is gone, so the AI update deals it 1000 damage before the Radioactive pulse comes due.
    return CreatureState(
        active=True,
        hp=50.0,
        max_hp=50.0,
        reward_value=100,
        move_speed=0,
        dot_tick_timer=-1,
        ai_mode=CreatureAiMode.FLANK_PLAYER_LINKED,
        link_index=1,
        type_id=CreatureTypeId.ALIEN,
    )


@pytest.mark.parametrize("preserve_bugs", [False, True])
def test_1_9_8_radioactive_burns_a_creature_killed_this_pass_only_with_preserve_bugs(preserve_bugs):
    reference = _step_radioactive(ClBuild.V1_9_93, preserve_bugs=preserve_bugs, creature=_linked_creature())
    world = _step_radioactive(ClBuild.V1_9_8, preserve_bugs=preserve_bugs, creature=_linked_creature())
    creature, reference_creature = world.creatures.entries[0], reference.creatures.entries[0]
    rng, reference_rng = world.state.rng, reference.state.rng
    assert isinstance(rng, RecordingCrand) and isinstance(reference_rng, RecordingCrand)
    assert reference_creature.hp < 0.0

    if preserve_bugs:
        # 1.9.8 has no hp gate: the corpse burns, pays its reward again and draws one more
        # `fx_queue_add_random` (original bug 56).
        assert creature.hp == x87_pc24_sub(reference_creature.hp, _PULSE_DAMAGE)
        assert creature.death_timer == x87_pc24_sub(reference_creature.death_timer, _DT)
        assert world.players[0].experience == reference.players[0].experience + 100
        assert_rng_progression(rng, before_calls=0, before_state=_SEED, expected_draws=reference_rng.calls + 4)
    else:
        assert (creature.hp, creature.death_timer) == (reference_creature.hp, reference_creature.death_timer)
        assert world.players[0].experience == reference.players[0].experience
        assert_rng_progression(
            rng,
            before_calls=0,
            before_state=_SEED,
            expected_draws=reference_rng.calls,
            expected_after_state=reference_rng.state,
        )
