from __future__ import annotations

from collections.abc import Sequence

from crimson.creatures.runtime import CreatureState, CreatureUpdateOptions
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.projectiles.runtime import ProjectileUpdateOptions
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState, WorldStepRuntime
from grim.geom import Vec2
from grim.rand import CrandLike


def make_creature_state(
    *,
    pos: Vec2,
    hp: float = 100.0,
    active: bool = True,
    lifecycle_stage: float = 16.0,
    size: float = 50.0,
    flags: CreatureFlags = CreatureFlags(0),
    plague_infected: bool = False,
    max_hp: float | None = None,
    type_id: CreatureTypeId = CreatureTypeId.ZOMBIE,
) -> CreatureState:
    hp_value = float(hp)
    return CreatureState(
        active=bool(active),
        type_id=type_id,
        pos=pos,
        hp=hp_value,
        max_hp=hp_value if max_hp is None else float(max_hp),
        lifecycle_stage=float(lifecycle_stage),
        size=float(size),
        flags=flags,
        plague_infected=bool(plague_infected),
    )


def make_creature_update_options(
    *,
    state: GameplayState,
    players: list[PlayerState],
    rng: CrandLike | None = None,
    detail_preset: int = 5,
    violence_disabled: int = 0,
    env: SpawnEnv | None = None,
    fx_queue: FxQueue | None = None,
    fx_queue_rotated: FxQueueRotated | None = None,
    quest_fail_retry_count: int = 0,
) -> CreatureUpdateOptions:
    default_env = SpawnEnv(
        demo_mode_active=bool(state.demo_mode_active),
        hardcore=bool(state.hardcore),
        quest_fail_retry_count=int(quest_fail_retry_count),
    )
    return CreatureUpdateOptions(
        state=state,
        players=players,
        rng=state.rng if rng is None else rng,
        env=default_env if env is None else env,
        fx_queue=FxQueue() if fx_queue is None else fx_queue,
        fx_queue_rotated=FxQueueRotated() if fx_queue_rotated is None else fx_queue_rotated,
        detail_preset=int(detail_preset),
        violence_disabled=int(violence_disabled),
    )


def make_step_runtime(
    world: WorldState,
    *,
    dt: float = 0.1,
    detail_preset: int = 5,
    violence_disabled: int = 0,
    game_mode: GameMode = GameMode.SURVIVAL,
    fx_queue: FxQueue | None = None,
) -> WorldStepRuntime:
    """The per-tick world context `WorldState.step` builds, for driving one subsystem directly."""

    return WorldStepRuntime(
        world=world,
        dt=float(dt),
        detail_preset=int(detail_preset),
        violence_disabled=int(violence_disabled),
        fx_queue=FxQueue() if fx_queue is None else fx_queue,
        game_mode=game_mode,
        hit_audio_game_tune_started=True,
        deaths=[],
        sfx=[],
    )


def place_creatures(world: WorldState, creatures: Sequence[CreatureState]) -> list[CreatureState]:
    """Put `creatures` into the first pool slots, so pool indices match list indices."""

    for idx, creature in enumerate(creatures):
        world.creatures.entries[idx] = creature
    return world.creatures.entries


def make_projectile_update_options(
    world: WorldState,
    *,
    step_runtime: WorldStepRuntime | None = None,
    detail_preset: int = 5,
) -> ProjectileUpdateOptions:
    return ProjectileUpdateOptions(
        rng=world.state.rng,
        runtime_state=world.state,
        players=world.players,
        step_runtime=make_step_runtime(world, detail_preset=detail_preset) if step_runtime is None else step_runtime,
        detail_preset=int(detail_preset),
    )
