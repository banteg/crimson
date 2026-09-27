from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.gameplay import player_update
from crimson.projectiles.runtime import ProjectileUpdateOptions
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState, WorldStepRuntime
from crimson.weapon_runtime.fire import WeaponFireCtx, WeaponFireResult, capture_fire_gate, fire_weapon
from grim.geom import Vec2


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
        fx_queue_rotated=FxQueueRotated(),
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


def step_player(
    world: WorldState,
    player: PlayerState,
    input_state: PlayerInput,
    dt: float,
    *,
    step_runtime: WorldStepRuntime | None = None,
) -> float:
    """Run `player_update` for one player the way `WorldState.step` does."""

    return player_update(
        player,
        input_state,
        dt,
        step_runtime=make_step_runtime(world, dt=dt) if step_runtime is None else step_runtime,
        reload_active_any=bool(input_state.reload_down or input_state.reload_pressed),
    )


def fire_player_weapon(
    world: WorldState,
    player: PlayerState,
    input_state: PlayerInput,
    dt: float,
    *,
    step_runtime: WorldStepRuntime | None = None,
) -> WeaponFireResult:
    """Fire `player`'s weapon with the gate `player_update` would capture right now."""

    return fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=input_state,
            dt=dt,
            step_runtime=make_step_runtime(world, dt=dt) if step_runtime is None else step_runtime,
            fire_gate=capture_fire_gate(player, world.state.perks),
        ),
    )


def step_creatures(world: WorldState, dt: float, **runtime_kwargs: Any) -> WorldStepRuntime:
    """Run `creature_update_all` for one frame; the runtime holds its deaths and sfx."""

    step_runtime = make_step_runtime(world, dt=dt, **runtime_kwargs)
    world.creatures.update(step_runtime)
    return step_runtime
