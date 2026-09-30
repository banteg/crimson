from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from crimson.aim_schemes import AimScheme
from crimson.creatures.runtime import CreatureDeath, CreatureState
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects import FxQueue, FxQueueRotated
from crimson.gameplay import player_update
from crimson.movement_controls import MovementControlType
from crimson.perks.availability import prepare_perk_availability
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PerkCounts, PlayerState
from crimson.sim.world_state import WorldState, WorldStepRuntime
from crimson.weapon_runtime import prepare_weapon_availability
from crimson.weapon_runtime.fire import WeaponFireCtx, WeaponFireResult, capture_fire_gate, fire_weapon
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


def make_step_runtime(world: WorldState, *, dt: float = 0.1, fx_queue: FxQueue | None = None) -> WorldStepRuntime:
    """The per-tick world context `WorldState.step` builds, for driving one subsystem directly.

    Subsystem tests start past the first projectile hit's game tune, so hits draw no playlist pick.
    """

    world.state.game_tune_started = True
    return WorldStepRuntime(
        world=world,
        dt=float(dt),
        fx_queue=FxQueue() if fx_queue is None else fx_queue,
        fx_queue_rotated=FxQueueRotated(),
        deaths=[],
        sfx=[],
    )


def kill_creature(
    world: WorldState,
    creature_index: int = 0,
    *,
    keep_corpse: bool = True,
    dt: float = 0.1,
    fx_queue: FxQueue | None = None,
) -> CreatureDeath:
    """Run `creature_handle_death` on one pool slot inside a fresh step runtime; returns its death event."""

    step_runtime = make_step_runtime(world, dt=dt, fx_queue=fx_queue)
    world.creatures.handle_death(step_runtime, creature_index, keep_corpse=keep_corpse)
    return step_runtime.deaths[-1]


def world_with_creature(
    creature: CreatureState,
    *,
    rng: CrandLike | None = None,
    perks: PerkCounts | None = None,
    players: Sequence[PlayerState] | None = None,
) -> WorldState:
    """A world holding `creature` in pool slot 0, for driving `creature_apply_damage` on it."""

    world = WorldState.build(hardcore=False, quest_fail_retry_count=0)
    prepare_weapon_availability(world.state)
    prepare_perk_availability(world.state)
    if rng is not None:
        world.state.rng = rng
    if perks is not None:
        world.state.perks = perks
    world.players.extend([PlayerState(index=0, pos=Vec2())] if players is None else players)
    world.creatures.entries[0] = creature
    return world


def place_creatures(world: WorldState, creatures: Sequence[CreatureState]) -> list[CreatureState]:
    """Put `creatures` into the first pool slots, so pool indices match list indices."""

    for idx, creature in enumerate(creatures):
        world.creatures.entries[idx] = creature
    return world.creatures.entries


def player_input(
    *,
    move_mode: MovementControlType = MovementControlType.DUAL_ACTION_PAD,
    aim_scheme: AimScheme = AimScheme.MOUSE,
    **fields: Any,
) -> PlayerInput:
    """A `PlayerInput` whose `move` steers as a dual action pad and whose `aim` is the mouse point; no movement key is held."""

    for key in ("move_forward_pressed", "move_backward_pressed", "turn_left_pressed", "turn_right_pressed"):
        fields.setdefault(key, False)
    return PlayerInput(move_mode=move_mode, aim_scheme=aim_scheme, **fields)


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
