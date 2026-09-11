"""Native inactive-target expiry witnesses, including the real world adapter."""

import json
from pathlib import Path

import pytest

from crimson.effects import FxQueue, ParticlePool, ParticleStyleId
from crimson.game_modes import GameMode
from crimson.owner_ref import OwnerRef
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState, _WorldStepRuntime
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand

FIXTURES = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/particle-bubble-expiry.json"


@pytest.mark.parametrize("witness", json.loads(FIXTURES.read_text()), ids=lambda case: str(case["index"]))
def test_inactive_bubble_expiry_matches_native_death_prelude(witness) -> None:
    case = witness["input"]
    assert case["fpcw"] == 0x7F
    world = WorldState.build(world_size=1024.0, demo_mode_active=True, hardcore=False, quest_fail_retry_count=0)
    world.players.append(PlayerState(index=0, pos=Vec2()))
    state = world.state
    rng = RecordingCrand(Crand(case["rng_seed"]))
    state.rng = rng
    state.particles = ParticlePool(rng=rng)
    state.survival_recent_death_count = case["history_count"]
    state.survival_reward_fire_seen = bool(case["fire_seen"])
    state.survival_reward_handout_enabled = bool(case["handout_enabled"])
    state.survival_recent_death_pos = [Vec2(*case["history_positions"][j : j + 2]) for j in (0, 2, 4)]
    item = case["creatures"][0]
    creature = world.creatures.entries[item["index"]]
    creature.active = False
    creature.pos = Vec2(item["x"], item["y"])
    previous_owner = creature.last_hit_owner
    for item in case["particles"]:
        particle = state.particles.entries[item["index"]]
        particle.active = True
        particle.render_flag = False
        particle.intensity = item["intensity"]
        particle.style_id = ParticleStyleId.BUBBLEGUN
        particle.target_id = item["target"]
        particle.owner = OwnerRef.from_player(0)
    runtime = _WorldStepRuntime(
        world=world,
        dt=case["dt"],
        world_size=1024.0,
        detail_preset=5,
        violence_disabled=0,
        fx_queue=FxQueue(),
        game_mode=GameMode.SURVIVAL,
        hit_audio_game_tune_started=True,
        deaths=[],
        sfx=[],
    )
    expired = state.particles.update(case["dt"], creatures=world.creatures.entries, creature_damage_runtime=runtime)
    assert expired == [item["index"] for item in case["particles"]]
    assert state.survival_recent_death_count == witness["history_count"]
    assert state.survival_reward_fire_seen == bool(witness["fire_seen"])
    assert state.survival_reward_handout_enabled == bool(witness["handout_enabled"])
    assert [v for pos in state.survival_recent_death_pos for v in (pos.x, pos.y)] == witness["history_positions"]
    assert len(runtime.deaths) == witness["death_calls"]
    assert not runtime.sfx and not runtime.hit_sfx
    assert rng.state == witness["rng_state"]
    assert rng.calls == 0
    assert not creature.active
    assert creature.last_hit_owner == previous_owner
