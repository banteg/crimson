from __future__ import annotations

from pathlib import Path

from crimson.bonuses import BonusId
from grim.geom import Vec2
from tests.support.world_runtime import WorldRuntimeHost


def test_bonus_pickup_spawns_burst_effect() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")

    player = world.sim_world.players[0]
    entry = world.sim_world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.POINTS,
        state=world.sim_world.state,
        emit_burst=False,
    )
    assert entry is not None

    assert not world.sim_world.state.effects.iter_active()
    world.step_survival_frame(0.016, perk_progression_enabled=False)

    assert entry.picked
    active = world.sim_world.state.effects.iter_active()
    assert len(active) == 12
    assert {effect.effect_id for effect in active} == {0}


def test_expired_bonus_can_still_pickup_as_unused_in_same_tick() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")

    player = world.sim_world.players[0]
    entry = world.sim_world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.FREEZE,
        state=world.sim_world.state,
        emit_burst=False,
    )
    assert entry is not None
    entry.time_left = 0.01
    world.sim_world.state.bonuses.freeze = 0.0

    world.step_survival_frame(0.016, perk_progression_enabled=False)

    assert entry.picked
    assert entry.bonus_id == BonusId.UNUSED
    assert world.sim_world.state.bonuses.freeze == 0.0
    active = world.sim_world.state.effects.iter_active()
    assert len(active) == 12
    assert {effect.effect_id for effect in active} == {0}
