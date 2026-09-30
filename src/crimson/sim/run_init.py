from __future__ import annotations

import msgspec

from grim.geom import Vec2

from ..game_modes import GameMode
from ..math_parity import x87_pc24_add
from ..persistence.save_status import GameStatus
from ..quests import quest_by_level
from ..quests.runtime import build_quest_spawn_table
from ..quests.status import tracked_quest_games_counter_index
from ..quests.types import QuestContext, QuestDefinition, SpawnEntry
from ..rng_caller_static import RngCallerStatic
from ..tutorial import reset_tutorial_state
from ..typo.state import reset_typo_state
from ..weapon_runtime import weapon_assign_player
from ..weapons import WeaponId
from .bootstrap import advance_gameplay_reset_rng
from .mode_updates import ModeState, QuestSpawnState, RushSpawnState, SurvivalSpawnState
from .run_spec import RunSpec
from .sessions import DeterministicSession
from .terrain_generate import TerrainSetup, terrain_generate, terrain_generate_random
from .world_reset import reset_world_players
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
    spawn_entries: tuple[SpawnEntry, ...] | None = None,
    start_weapon_id: WeaponId | None = None,
) -> PreparedRun:
    """Build a fresh run, preserving native startup order and RNG consumption.

    A live caller may supply its save object so gameplay writes remain persistent.
    Playback owns a detached copy of the same pre-start status snapshot.
    """
    quest = None
    if spec.game_mode_id == GameMode.QUESTS:
        if spec.quest_level is None:
            raise ValueError("quest runs require a quest_level")
        quest = quest_by_level(spec.quest_level)
        if quest is None:
            raise ValueError(f"unknown quest_level={spec.quest_level.text!r}")

    world = WorldState.build(
        hardcore=spec.hardcore,
        quest_fail_retry_count=spec.quest_fail_retry_count, preserve_bugs=spec.preserve_bugs,
    )
    world.state.rng.srand(spec.seed)
    world.state.detail_preset = spec.detail_preset
    world.state.violence_disabled = spec.violence_disabled
    world.state.friendly_fire_enabled = spec.friendly_fire
    world.creatures.apply_gameplay_reset_target_players(spec.player_count)
    reset_world_players(world.players, state=world.state, player_count=spec.player_count)
    world.state.status = GameStatus.detached(spec.status.as_status_data()) if status is None else status
    # The seed is the rng entering `gameplay_reset_state()`, which every mode's run start calls.
    for creature, anim_phase in zip(world.creatures.entries, advance_gameplay_reset_rng(world.state.rng), strict=True):
        creature.anim_phase = anim_phase
    terrain = terrain_generate_random(world.state.rng, spec.status.quest_unlock_index)
    world.state.game_mode = spec.game_mode_id
    highscore_tag = 0
    mode_state: ModeState = None
    match spec.game_mode_id:
        case GameMode.SURVIVAL:
            mode_state = SurvivalSpawnState()
        case GameMode.RUSH:
            mode_state = RushSpawnState()
        case GameMode.QUESTS:
            assert quest is not None
            # `quest_start_selected` draws the score tag, then generates the quest terrain over the
            # reset's random one: that first terrain's draws stay, its stamps are never shown.
            highscore_tag = world.state.rng.rand_tagged(RngCallerStatic.QUEST_START_SELECTED_HIGHSCORE_RANDOM_TAG)
            terrain = terrain_generate(world.state.rng, quest.terrain_slots)
            generated_entries = build_quest_spawn_table(
                quest, QuestContext(player_count=spec.player_count, hardcore=spec.hardcore, rng=world.state.rng),
            )
            world.state.quest_level = quest.level
            weapon_id = quest.start_weapon_id if start_weapon_id is None else start_weapon_id
            if weapon_id == WeaponId.NONE:
                weapon_id = WeaponId.PISTOL
            for player in world.players:
                weapon_assign_player(player, weapon_id, state=world.state)
            entries = generated_entries if spawn_entries is None else spawn_entries
            mode_state = QuestSpawnState(spawn_entries=entries, total_creatures=sum(entry.count for entry in entries))
            index = tracked_quest_games_counter_index(quest.level)
            if index is not None:
                world.state.status.increment_quest_play_count(index)
        case GameMode.TYPO:
            reset_typo_state(
                world.state.typo,
                creature_capacity=len(world.creatures.entries),
                dictionary_words=spec.typo_dictionary_words,
                highscore_names=spec.typo_highscore_names,
            )
            # Native's static aim point starts 128 units right of player 1 on the process's first
            # Typ-o frame and carries over between runs; each port run starts fresh.
            player = world.players[0]
            world.state.typo.target_world = Vec2(x87_pc24_add(player.pos.x, 128.0), player.pos.y)
        case GameMode.TUTORIAL:
            weapon_assign_player(world.players[0], WeaponId.PISTOL, state=world.state)
            reset_tutorial_state(world.state.tutorial, world.state.tutorial_overlay)
        case _:
            raise ValueError(f"unsupported replay game_mode_id={int(spec.game_mode_id)}")
    session = DeterministicSession(
        world=world,
        # `gameplay_update_and_render` levels up outside Rush; Typ-o runs its own frame.
        perk_progression_enabled=spec.game_mode_id not in (GameMode.RUSH, GameMode.TYPO),
        mode_state=mode_state,
    )
    # Run setup happens inside a frame; `game_frame_update` ends it with its discarded draw.
    world.state.rng.rand_tagged(RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED)
    return PreparedRun(session=session, terrain=terrain, quest=quest, quest_highscore_random_tag=highscore_tag)
