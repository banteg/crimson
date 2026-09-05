from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import msgspec

from crimson.sim.world_reset import reset_world_players
from grim.geom import Vec2

from ...effects import FxQueue, FxQueueRotated
from ...game_modes import GameMode
from ...math_parity import f32
from ...persistence.save_status import GameStatus, GameStatusData
from ...sim.state_types import PlayerState
from ...sim.step_pipeline import time_scale_reflex_boost_bonus as _time_scale_reflex_boost_bonus
from ...weapon_runtime import most_used_weapon_id_for_player
from ...weapons import WeaponId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState



class ReplayRunnerError(ValueError):
    pass


class RunResult(msgspec.Struct, frozen=True):
    game_mode_id: GameMode
    tick_rate: int
    ticks: int
    elapsed_ms: int
    score_xp: int
    creature_kill_count: int
    most_used_weapon_id: WeaponId
    shots_fired: int
    shots_hit: int
    rng_state: int

def build_empty_fx_queues() -> tuple[FxQueue, FxQueueRotated]:
    # Headless runners still need FX queues to satisfy sim APIs.
    return FxQueue(), FxQueueRotated()


def status_from_replay_status_fields(
    *,
    quest_unlock_index: int,
    quest_unlock_index_full: int,
    weapon_usage_counts: tuple[int, ...] = (),
) -> GameStatus:
    return GameStatus.from_data(
        path=Path("replay://status"),
        data=GameStatusData(
            quest_unlock_index=int(quest_unlock_index),
            quest_unlock_index_full=int(quest_unlock_index_full),
            weapon_usage_counts=tuple(weapon_usage_counts),
        ),
    )


def reset_players(
    players: list[PlayerState],
    *,
    state: GameplayState,
    world_size: float,
    player_count: int,
    spawn_pos: Vec2 | None = None,
) -> None:
    """Reset `players` to the classic initial layout used by runtime reset."""

    reset_world_players(
        players,
        state=state,
        world_size=float(world_size),
        player_count=int(player_count),
        spawn_pos=spawn_pos,
    )


def player0_shots(state: GameplayState) -> tuple[int, int]:
    if len(state.shots_fired) <= 0 or len(state.shots_hit) <= 0:
        return 0, 0
    fired = int(state.shots_fired[0])
    hit = int(state.shots_hit[0])
    fired = max(0, int(fired))
    hit = max(0, min(int(hit), fired))
    return fired, hit


def player0_most_used_weapon_id(state: GameplayState, players: list[PlayerState]) -> WeaponId:
    fallback_weapon_id = WeaponId.PISTOL
    if players:
        fallback_weapon_id = players[0].weapon.weapon_id
    return most_used_weapon_id_for_player(state, player_index=0, fallback_weapon_id=fallback_weapon_id)


def time_scale_reflex_boost_bonus(state: GameplayState, dt: float) -> float:
    """Time scale (Reflex Boost bonus), mirroring deterministic world-step timing."""
    return _time_scale_reflex_boost_bonus(
        reflex_boost_timer=float(state.bonuses.reflex_boost),
        time_scale_active=bool(state.time_scale_active),
        dt=float(dt),
    )


def time_scale_reflex_boost_bonus_f32(state: GameplayState, dt: float) -> float:
    """Time scale, preserving native float32 input rounding (dt_f32)."""
    dt_f32 = f32(float(dt))
    return time_scale_reflex_boost_bonus(state, float(dt_f32))
