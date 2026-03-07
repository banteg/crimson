from __future__ import annotations

from collections.abc import Callable
from typing import TypeAlias

from ..effects import FxQueue, FxQueueRotated
from ..game_modes import GameMode
from ..quests.level import QuestLevel
from ..quests.types import SpawnEntry
from ..sim.world_state import WorldState
from ..weapon_runtime import weapon_assign_player
from ..weapons import WeaponId
from .sessions import (
    DeterministicSession,
    QuestSpawnState,
    RushSpawnState,
    SurvivalSpawnState,
    quest_post_step,
    rush_input_transform,
    rush_mid_step,
    survival_mid_step,
)

DeterministicSessionFactory: TypeAlias = Callable[..., DeterministicSession]

RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE
RUSH_FORCED_AMMO = 30.0


def enforce_rush_loadout(world: WorldState) -> None:
    for player in world.players:
        if player.weapon.weapon_id != RUSH_WEAPON_ID:
            weapon_assign_player(player, RUSH_WEAPON_ID, state=world.state)
        # Native `rush_mode_update` forces assault rifle + 30 ammo every frame.
        player.weapon.ammo = float(RUSH_FORCED_AMMO)


def build_survival_session(
    *,
    world: WorldState,
    world_size: float,
    damage_scale_by_type: dict[int, float],
    fx_queue: FxQueue,
    fx_queue_rotated: FxQueueRotated,
    detail_preset: int,
    gore_disabled: int,
    game_tune_started: bool,
    clear_fx_queues_each_tick: bool,
    finalize_post_render_lifecycle: bool,
    apply_world_dt_steps: bool = False,
    session_factory: DeterministicSessionFactory = DeterministicSession,
) -> tuple[DeterministicSession, SurvivalSpawnState]:
    spawn_state = SurvivalSpawnState()
    session = session_factory(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=damage_scale_by_type,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=True,
        detail_preset=int(detail_preset),
        gore_disabled=int(gore_disabled),
        game_tune_started=bool(game_tune_started),
        apply_world_dt_steps=bool(apply_world_dt_steps),
        clear_fx_queues_each_tick=bool(clear_fx_queues_each_tick),
        finalize_post_render_lifecycle=bool(finalize_post_render_lifecycle),
        mid_step_hook=lambda ctx: survival_mid_step(ctx, spawn_state),
    )
    return session, spawn_state


def build_rush_session(
    *,
    world: WorldState,
    world_size: float,
    damage_scale_by_type: dict[int, float],
    fx_queue: FxQueue,
    fx_queue_rotated: FxQueueRotated,
    detail_preset: int,
    gore_disabled: int,
    game_tune_started: bool,
    clear_fx_queues_each_tick: bool,
    finalize_post_render_lifecycle: bool,
    session_factory: DeterministicSessionFactory = DeterministicSession,
) -> tuple[DeterministicSession, RushSpawnState]:
    spawn_state = RushSpawnState()
    session = session_factory(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=damage_scale_by_type,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        game_mode=GameMode.RUSH,
        perk_progression_enabled=False,
        detail_preset=int(detail_preset),
        gore_disabled=int(gore_disabled),
        game_tune_started=bool(game_tune_started),
        clear_fx_queues_each_tick=bool(clear_fx_queues_each_tick),
        finalize_post_render_lifecycle=bool(finalize_post_render_lifecycle),
        elapsed_uses_raw_dt=True,
        mid_step_hook=lambda ctx: rush_mid_step(ctx, spawn_state),
        before_step_hook=lambda: enforce_rush_loadout(world),
        input_transform=rush_input_transform,
    )
    return session, spawn_state


def build_quest_session(
    *,
    world: WorldState,
    world_size: float,
    damage_scale_by_type: dict[int, float],
    fx_queue: FxQueue,
    fx_queue_rotated: FxQueueRotated,
    detail_preset: int,
    gore_disabled: int,
    game_tune_started: bool,
    demo_mode_active: bool,
    apply_world_dt_steps: bool,
    clear_fx_queues_each_tick: bool,
    finalize_post_render_lifecycle: bool,
    spawn_entries: tuple[SpawnEntry, ...],
    quest_level: QuestLevel | None,
    start_weapon_id: WeaponId | None,
    session_factory: DeterministicSessionFactory = DeterministicSession,
) -> tuple[DeterministicSession, QuestSpawnState]:
    world.state.quest_level = quest_level

    weapon_id = WeaponId.PISTOL if start_weapon_id in (None, WeaponId.NONE) else start_weapon_id
    for player in world.players:
        weapon_assign_player(player, weapon_id, state=world.state)

    world.creatures.capture_spawn_events_authoritative = False
    quest_state = QuestSpawnState(spawn_entries=tuple(spawn_entries))
    session = session_factory(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=damage_scale_by_type,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        game_mode=GameMode.QUESTS,
        perk_progression_enabled=True,
        detail_preset=int(detail_preset),
        gore_disabled=int(gore_disabled),
        game_tune_started=bool(game_tune_started),
        demo_mode_active=bool(demo_mode_active),
        apply_world_dt_steps=bool(apply_world_dt_steps),
        clear_fx_queues_each_tick=bool(clear_fx_queues_each_tick),
        finalize_post_render_lifecycle=bool(finalize_post_render_lifecycle),
        post_step_hook=lambda ctx: quest_post_step(ctx, quest_state),
    )
    return session, quest_state
