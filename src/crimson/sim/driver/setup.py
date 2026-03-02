from __future__ import annotations

import math
from pathlib import Path
from typing import cast

import msgspec

from grim.geom import Vec2

from ...effects import FxQueue, FxQueueRotated
from ...game_modes import GameMode
from ...math_parity import f32
from ...persistence.save_status import GameStatus
from ...replay.types import ReplayStatusSnapshot
from ...status_snapshot import game_status_from_progress_status, progress_status_from_replay
from ...weapon_runtime import init_default_alt_weapon, most_used_weapon_id_for_player, weapon_assign_player
from ...weapons import WEAPON_TABLE, WeaponId
from ..state_types import GameplayState, PlayerState
from ..step_pipeline import time_scale_reflex_boost_bonus as _time_scale_reflex_boost_bonus


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

def build_damage_scale_by_type() -> dict[int, float]:
    damage_scale_by_type: dict[int, float] = {}
    for entry in WEAPON_TABLE:
        if entry.weapon_id <= WeaponId.NONE:
            continue
        damage_scale_by_type[entry.weapon_id] = float(cast(float, entry.damage_scale))
    return damage_scale_by_type


def build_empty_fx_queues() -> tuple[FxQueue, FxQueueRotated]:
    # Headless runners still need FX queues to satisfy sim APIs.
    return FxQueue(), FxQueueRotated()


def status_from_snapshot(
    *,
    quest_unlock_index: int,
    quest_unlock_index_full: int,
    weapon_usage_counts: tuple[int, ...] | None = None,
) -> GameStatus:
    replay_status = ReplayStatusSnapshot(
        quest_unlock_index=int(quest_unlock_index),
        quest_unlock_index_full=int(quest_unlock_index_full),
        weapon_usage_counts=tuple(weapon_usage_counts or ()),
    )
    progress = progress_status_from_replay(replay_status)
    return game_status_from_progress_status(progress, path=Path("replay://status"))


def reset_players(
    players: list[PlayerState],
    *,
    world_size: float,
    player_count: int,
    spawn_pos: Vec2 | None = None,
) -> None:
    """Reset `players` to the classic initial layout used by `GameWorld.reset`."""

    players.clear()

    base = Vec2(float(world_size) * 0.5, float(world_size) * 0.5) if spawn_pos is None else spawn_pos
    count = max(1, int(player_count))
    if count <= 1:
        offsets = [Vec2()]
    else:
        radius = 32.0
        step = math.tau / float(count)
        offsets = [Vec2.from_angle(float(idx) * step) * radius for idx in range(count)]

    for idx in range(count):
        pos = (base + offsets[idx]).clamp_rect(0.0, 0.0, float(world_size), float(world_size))
        player = PlayerState(index=idx, pos=pos)
        weapon_assign_player(player, WeaponId.PISTOL)
        init_default_alt_weapon(player)
        players.append(player)


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
    """Time scale (Reflex Boost bonus), mirroring `GameWorld.update`."""
    return _time_scale_reflex_boost_bonus(
        reflex_boost_timer=float(state.bonuses.reflex_boost),
        time_scale_active=bool(state.time_scale_active),
        dt=float(dt),
    )


def time_scale_reflex_boost_bonus_f32(state: GameplayState, dt: float) -> float:
    """Time scale, preserving native float32 input rounding (dt_f32)."""
    dt_f32 = f32(float(dt))
    return time_scale_reflex_boost_bonus(state, float(dt_f32))
