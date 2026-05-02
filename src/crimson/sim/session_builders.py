from __future__ import annotations

from ..game_modes import GameMode
from ..quests.level import QuestLevel
from ..quests.types import SpawnEntry
from ..sim.world_state import WorldState
from ..tutorial import reset_tutorial_state
from ..typo.state import reset_typo_state
from ..weapon_runtime import weapon_assign_player
from ..weapons import WeaponId
from .sessions import (
    DeterministicSession,
    QuestSessionRuntime,
    QuestSpawnState,
    RushSessionRuntime,
    RushSpawnState,
    SurvivalSessionRuntime,
    SurvivalSpawnState,
    TutorialSessionRuntime,
    TypoSessionRuntime,
)


def build_survival_session(
    *,
    world: WorldState,
    world_size: float,
    damage_scale_by_type: dict[int, float],
    detail_preset: int,
    violence_disabled: int,
    game_tune_started: bool,
    finalize_post_render_lifecycle: bool,
    apply_world_dt_steps: bool = False,
) -> tuple[DeterministicSession, SurvivalSpawnState]:
    mode_runtime = SurvivalSessionRuntime()
    session = DeterministicSession(
        world=world,
        world_size=world_size,
        damage_scale_by_type=damage_scale_by_type,
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=True,
        detail_preset=detail_preset,
        violence_disabled=violence_disabled,
        game_tune_started=game_tune_started,
        apply_world_dt_steps=apply_world_dt_steps,
        finalize_post_render_lifecycle=finalize_post_render_lifecycle,
        mode_runtime=mode_runtime,
    )
    return session, mode_runtime.spawn


def build_rush_session(
    *,
    world: WorldState,
    world_size: float,
    damage_scale_by_type: dict[int, float],
    detail_preset: int,
    violence_disabled: int,
    game_tune_started: bool,
    finalize_post_render_lifecycle: bool,
) -> tuple[DeterministicSession, RushSpawnState]:
    mode_runtime = RushSessionRuntime(world=world)
    session = DeterministicSession(
        world=world,
        world_size=world_size,
        damage_scale_by_type=damage_scale_by_type,
        game_mode=GameMode.RUSH,
        perk_progression_enabled=False,
        detail_preset=detail_preset,
        violence_disabled=violence_disabled,
        game_tune_started=game_tune_started,
        finalize_post_render_lifecycle=finalize_post_render_lifecycle,
        elapsed_uses_raw_dt=True,
        mode_runtime=mode_runtime,
    )
    return session, mode_runtime.spawn


def build_quest_session(
    *,
    world: WorldState,
    world_size: float,
    damage_scale_by_type: dict[int, float],
    detail_preset: int,
    violence_disabled: int,
    game_tune_started: bool,
    demo_mode_active: bool,
    apply_world_dt_steps: bool,
    finalize_post_render_lifecycle: bool,
    spawn_entries: tuple[SpawnEntry, ...],
    quest_level: QuestLevel | None,
    start_weapon_id: WeaponId | None,
) -> tuple[DeterministicSession, QuestSpawnState]:
    world.state.quest_level = quest_level

    weapon_id = WeaponId.PISTOL if start_weapon_id in (None, WeaponId.NONE) else start_weapon_id
    for player in world.players:
        weapon_assign_player(player, weapon_id, state=world.state)

    world.creatures.capture_spawn_events_authoritative = False
    quest_state = QuestSpawnState(spawn_entries=tuple(spawn_entries))
    mode_runtime = QuestSessionRuntime(spawn=quest_state)
    session = DeterministicSession(
        world=world,
        world_size=world_size,
        damage_scale_by_type=damage_scale_by_type,
        game_mode=GameMode.QUESTS,
        perk_progression_enabled=True,
        detail_preset=detail_preset,
        violence_disabled=violence_disabled,
        game_tune_started=game_tune_started,
        demo_mode_active=demo_mode_active,
        apply_world_dt_steps=apply_world_dt_steps,
        finalize_post_render_lifecycle=finalize_post_render_lifecycle,
        mode_runtime=mode_runtime,
    )
    return session, quest_state


def build_typo_session(
    *,
    world: WorldState,
    world_size: float,
    damage_scale_by_type: dict[int, float],
    detail_preset: int,
    violence_disabled: int,
    game_tune_started: bool,
    dictionary_words: tuple[str, ...] = (),
    highscore_names: tuple[str, ...] = (),
) -> DeterministicSession:
    reset_typo_state(
        world.state.typo,
        creature_capacity=len(world.creatures.entries),
        dictionary_words=dictionary_words,
        highscore_names=highscore_names,
    )
    session = DeterministicSession(
        world=world,
        world_size=world_size,
        damage_scale_by_type=damage_scale_by_type,
        game_mode=GameMode.TYPO,
        perk_progression_enabled=False,
        detail_preset=detail_preset,
        violence_disabled=violence_disabled,
        game_tune_started=game_tune_started,
        mode_runtime=TypoSessionRuntime(world=world),
    )
    return session


def build_tutorial_session(
    *,
    world: WorldState,
    world_size: float,
    damage_scale_by_type: dict[int, float],
    detail_preset: int,
    violence_disabled: int,
    game_tune_started: bool,
    demo_mode_active: bool,
) -> DeterministicSession:
    reset_tutorial_state(
        world.state.tutorial,
        world.state.tutorial_overlay,
        preserve_bugs=world.state.preserve_bugs,
    )
    session = DeterministicSession(
        world=world,
        world_size=world_size,
        damage_scale_by_type=damage_scale_by_type,
        game_mode=GameMode.TUTORIAL,
        perk_progression_enabled=True,
        detail_preset=detail_preset,
        violence_disabled=violence_disabled,
        game_tune_started=game_tune_started,
        demo_mode_active=demo_mode_active,
        mode_runtime=TutorialSessionRuntime(world=world),
    )
    return session
