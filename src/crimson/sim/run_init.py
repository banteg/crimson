from __future__ import annotations

from pathlib import Path

import msgspec

from ..game_modes import GameMode
from ..persistence.save_status import GameStatus
from ..quests import quest_by_level
from ..quests.runtime import build_quest_spawn_table
from ..quests.status import tracked_quest_games_counter_index
from ..quests.types import QuestContext, QuestDefinition, SpawnEntry
from ..rng_caller_static import RngCallerStatic
from ..weapons import WeaponId, build_damage_scale_by_type
from .bootstrap import TerrainSetup, advance_explicit_terrain, advance_unlock_terrain
from .run_spec import WORLD_SIZE, RunSpec
from .session_builders import (
    build_quest_session,
    build_rush_session,
    build_survival_session,
    build_tutorial_session,
    build_typo_session,
)
from .sessions import DeterministicSession, enforce_rush_loadout
from .world_reset import CreatureSlotResidue, apply_creature_pool_residue, reset_world_players
from .world_state import WorldState


class PreparedRun(msgspec.Struct, frozen=True):
    session: DeterministicSession
    terrain: TerrainSetup
    quest: QuestDefinition | None = None
    quest_highscore_random_tag: int = 0


def initialize_run(
    spec: RunSpec,
    *,
    status: GameStatus | None = None,
    apply_world_dt_steps: bool = True,
    creature_pool_residue: tuple[CreatureSlotResidue, ...] | None = None,
    spawn_entries: tuple[SpawnEntry, ...] | None = None,
    start_weapon_id: WeaponId | None = None,
) -> PreparedRun:
    """Build a fresh run, preserving native startup order and RNG consumption.

    A live caller may supply its save object so gameplay writes remain persistent.
    Playback owns a detached copy of the same pre-start status snapshot. Original
    captures seed creature-slot residue and pre-transformed frame deltas; port
    runs always start from a fresh pool.
    """
    quest = None
    if spec.game_mode_id == GameMode.QUESTS:
        if spec.quest_level is None:
            raise ValueError("quest runs require a quest_level")
        quest = quest_by_level(spec.quest_level)
        if quest is None:
            raise ValueError(f"unknown quest_level={spec.quest_level.text!r}")

    world = WorldState.build(
        world_size=WORLD_SIZE, demo_mode_active=spec.demo, hardcore=spec.hardcore,
        quest_fail_retry_count=spec.quest_fail_retry_count, preserve_bugs=spec.preserve_bugs,
    )
    world.state.rng.srand(spec.seed)
    world.creatures.apply_gameplay_reset_target_players(spec.player_count)
    if creature_pool_residue is not None:
        apply_creature_pool_residue(world.creatures.entries, creature_pool_residue)
    reset_world_players(world.players, state=world.state, world_size=WORLD_SIZE, player_count=spec.player_count)
    world.state.status = status if status is not None else GameStatus.from_data(
        path=Path("run://status"), data=spec.status.as_status_data(), dirty=False,
    )
    terrain = advance_unlock_terrain(
        world.state.rng, unlock_index=spec.status.quest_unlock_index, width=int(WORLD_SIZE), height=int(WORLD_SIZE),
    )
    damage = build_damage_scale_by_type()
    highscore_tag = 0
    match spec.game_mode_id:
        case GameMode.SURVIVAL:
            session, _ = build_survival_session(
                world=world, world_size=WORLD_SIZE, damage_scale_by_type=damage,
                detail_preset=spec.detail_preset, violence_disabled=spec.violence_disabled,
                game_tune_started=False, finalize_post_render_lifecycle=True, apply_world_dt_steps=apply_world_dt_steps,
            )
        case GameMode.RUSH:
            enforce_rush_loadout(world)
            session, _ = build_rush_session(
                world=world, world_size=WORLD_SIZE, damage_scale_by_type=damage,
                detail_preset=spec.detail_preset, violence_disabled=spec.violence_disabled,
                game_tune_started=False, finalize_post_render_lifecycle=True,
            )
        case GameMode.QUESTS:
            assert quest is not None
            # Native burns the score tag between generic and quest terrain setup.
            highscore_tag = world.state.rng.rand_tagged(RngCallerStatic.QUEST_START_SELECTED_HIGHSCORE_RANDOM_TAG)
            terrain = advance_explicit_terrain(
                world.state.rng, terrain_slots=quest.terrain_slots, width=int(WORLD_SIZE), height=int(WORLD_SIZE),
            )
            generated_entries = tuple(build_quest_spawn_table(
                quest, QuestContext(width=int(WORLD_SIZE), height=int(WORLD_SIZE), player_count=spec.player_count),
                rng=world.state.rng, hardcore=spec.hardcore, full_version=not spec.demo,
            ))
            session, _ = build_quest_session(
                world=world, world_size=WORLD_SIZE, damage_scale_by_type=damage,
                detail_preset=spec.detail_preset, violence_disabled=spec.violence_disabled,
                game_tune_started=False, finalize_post_render_lifecycle=True, apply_world_dt_steps=apply_world_dt_steps,
                demo_mode_active=spec.demo, quest_level=quest.level,
                start_weapon_id=quest.start_weapon_id if start_weapon_id is None else start_weapon_id,
                spawn_entries=generated_entries if spawn_entries is None else spawn_entries,
            )
            index = tracked_quest_games_counter_index(quest.level)
            if index is not None:
                world.state.status.increment_quest_play_count(index)
        case GameMode.TYPO:
            session = build_typo_session(
                world=world, world_size=WORLD_SIZE, damage_scale_by_type=damage,
                detail_preset=spec.detail_preset, violence_disabled=spec.violence_disabled, game_tune_started=False,
                finalize_post_render_lifecycle=True, dictionary_words=spec.typo_dictionary_words, highscore_names=spec.typo_highscore_names,
            )
        case GameMode.TUTORIAL:
            session = build_tutorial_session(
                world=world, world_size=WORLD_SIZE, damage_scale_by_type=damage,
                detail_preset=spec.detail_preset, violence_disabled=spec.violence_disabled, game_tune_started=False,
                finalize_post_render_lifecycle=True, demo_mode_active=spec.demo,
            )
        case _:
            raise ValueError(f"unsupported replay game_mode_id={int(spec.game_mode_id)}")
    return PreparedRun(session=session, terrain=terrain, quest=quest, quest_highscore_random_tag=highscore_tag)
