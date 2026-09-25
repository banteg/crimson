from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import TYPE_CHECKING

import msgspec

from ..game_modes import GameMode
from ..math_parity import f32
from ..quests.results import compute_quest_final_time
from ..typo.state import typo_shot_counts
from ..weapon_runtime import most_used_weapon_id_for_player
from ..weapons import WeaponId
from .state_types import PlayerState

if TYPE_CHECKING:
    from .sessions import DeterministicSession


class RunOutcome(StrEnum):
    DEATH = "death"
    QUEST_COMPLETED = "quest_completed"
    TUTORIAL_COMPLETED = "tutorial_completed"
    INCOMPLETE = "incomplete"


class PlayerRunResult(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    experience: int
    health: float
    shots_fired: int
    shots_hit: int
    most_used_weapon_id: WeaponId


class RunResult(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Authoritative end-of-run state, derived identically by live play and verification."""

    outcome: RunOutcome
    elapsed_ms: int
    kills: int
    rng_state: int
    pending_perks: int
    # Only set for completed quests: base time minus life and unpicked-perk bonuses.
    quest_final_ms: int | None
    players: tuple[PlayerRunResult, ...]


def all_players_dead(players: Sequence[PlayerState]) -> bool:
    return bool(players) and all(float(player.health) <= 0.0 for player in players)


def death_transition_ready(players: Sequence[PlayerState]) -> bool:
    """Every player is dead and their death animation has finished."""

    return all_players_dead(players) and all(float(player.death_timer) < 0.0 for player in players)


def build_run_result(session: DeterministicSession, *, outcome: RunOutcome) -> RunResult:
    world = session.world
    state = world.state
    players = world.players
    elapsed_ms = session.run_elapsed_ms

    player_results: list[PlayerRunResult] = []
    for index, player in enumerate(players):
        if session.game_mode == GameMode.TYPO:
            shots_fired, shots_hit = typo_shot_counts(state.typo)
        else:
            # Piercing shots can hit several creatures; the high-score record
            # clamps hits to shots fired.
            shots_fired = max(0, int(state.shots_fired[index]))
            shots_hit = max(0, min(int(state.shots_hit[index]), shots_fired))
        player_results.append(
            PlayerRunResult(
                experience=int(player.experience),
                health=float(f32(float(player.health))),
                shots_fired=int(shots_fired),
                shots_hit=int(shots_hit),
                most_used_weapon_id=most_used_weapon_id_for_player(
                    state,
                    player_index=index,
                    fallback_weapon_id=player.weapon.weapon_id,
                ),
            ),
        )

    quest_final_ms = None
    if outcome == RunOutcome.QUEST_COMPLETED:
        quest_final_ms = compute_quest_final_time(
            base_time_ms=int(elapsed_ms),
            player_health=float(players[0].health),
            pending_perk_count=int(state.perk_selection.pending_count),
            player_health_values=tuple(float(player.health) for player in players),
        ).final_time_ms

    return RunResult(
        outcome=outcome,
        elapsed_ms=int(elapsed_ms),
        kills=int(world.creatures.kill_count),
        rng_state=int(state.rng.state) & 0xFFFFFFFF,
        pending_perks=int(state.perk_selection.pending_count),
        quest_final_ms=quest_final_ms,
        players=tuple(player_results),
    )


def run_result_mismatches(expected: RunResult, actual: RunResult) -> list[str]:
    """Field paths where two results differ, in declared order."""

    mismatches = [
        field
        for field in RunResult.__struct_fields__
        if field != "players" and getattr(expected, field) != getattr(actual, field)
    ]
    if len(expected.players) != len(actual.players):
        mismatches.append("players")
        return mismatches
    for index, (expected_player, actual_player) in enumerate(zip(expected.players, actual.players, strict=True)):
        mismatches.extend(
            f"players[{index}].{field}"
            for field in PlayerRunResult.__struct_fields__
            if getattr(expected_player, field) != getattr(actual_player, field)
        )
    return mismatches
