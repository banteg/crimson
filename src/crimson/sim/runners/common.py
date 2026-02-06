from __future__ import annotations

from grim.geom import Vec2

from dataclasses import dataclass
import math
from pathlib import Path

from ...effects import FxQueue, FxQueueRotated
from ...gameplay import GameplayState, PlayerState, most_used_weapon_id_for_player, weapon_assign_player
from ...persistence.save_status import WEAPON_USAGE_COUNT, GameStatus, default_status_data
from ...weapons import WEAPON_TABLE


class ReplayRunnerError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RunResult:
    game_mode_id: int
    tick_rate: int
    ticks: int
    elapsed_ms: int
    score_xp: int
    creature_kill_count: int
    most_used_weapon_id: int
    shots_fired: int
    shots_hit: int
    rng_state: int


def build_damage_scale_by_type() -> dict[int, float]:
    damage_scale_by_type: dict[int, float] = {}
    for entry in WEAPON_TABLE:
        if int(entry.weapon_id) <= 0:
            continue
        damage_scale_by_type[int(entry.weapon_id)] = float(entry.damage_scale or 1.0)
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
    data = default_status_data()
    data["quest_unlock_index"] = int(quest_unlock_index) & 0xFFFF
    data["quest_unlock_index_full"] = int(quest_unlock_index_full) & 0xFFFF

    if weapon_usage_counts is not None:
        counts = list(data.get("weapon_usage_counts") or [0] * WEAPON_USAGE_COUNT)
        if len(counts) != WEAPON_USAGE_COUNT:
            counts = [0] * WEAPON_USAGE_COUNT
        for idx, value in enumerate(weapon_usage_counts[:WEAPON_USAGE_COUNT]):
            counts[idx] = int(value) & 0xFFFFFFFF
        data["weapon_usage_counts"] = counts

    return GameStatus(path=Path("replay://status"), data=data)


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
        weapon_assign_player(player, 1)
        players.append(player)


def player0_shots(state: GameplayState) -> tuple[int, int]:
    fired = 0
    hit = 0
    try:
        fired = int(state.shots_fired[0])
        hit = int(state.shots_hit[0])
    except Exception:
        fired = 0
        hit = 0

    fired = max(0, int(fired))
    hit = max(0, min(int(hit), fired))
    return fired, hit


def player0_most_used_weapon_id(state: GameplayState, players: list[PlayerState]) -> int:
    fallback_weapon_id = 1
    if players:
        fallback_weapon_id = int(players[0].weapon_id)
    return most_used_weapon_id_for_player(state, player_index=0, fallback_weapon_id=fallback_weapon_id)


def time_scale_reflex_boost_bonus(state: GameplayState, dt: float) -> float:
    """Time scale (Reflex Boost bonus), mirroring `GameWorld.update`."""

    if not (float(dt) > 0.0):
        return float(dt)
    if not (float(state.bonuses.reflex_boost) > 0.0):
        return float(dt)

    time_scale_factor = 0.3
    timer = float(state.bonuses.reflex_boost)
    if timer < 1.0:
        time_scale_factor = (1.0 - timer) * 0.7 + 0.3
    return float(dt) * float(time_scale_factor)
