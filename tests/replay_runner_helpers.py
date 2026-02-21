from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.sim.input import PlayerInput
from grim.geom import Vec2


def _blank_survival_replay(*, ticks: int, seed: int = 0xBEEF, game_version: str = "0.0.0") -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=game_version,
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _blank_rush_replay(*, ticks: int, seed: int = 0xBEEF, game_version: str = "0.0.0") -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.RUSH),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=game_version,
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _blank_quest_replay(*, ticks: int, seed: int = 101, game_version: str = "0.0.0") -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.QUESTS),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=game_version,
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _quest_spawn_entries(level: str = "1.1", *, player_count: int = 1, seed: int = 101):
    quest = quest_by_level(level)
    assert quest is not None
    ctx = QuestContext(width=1024, height=1024, player_count=int(player_count))
    return build_quest_spawn_table(
        quest,
        ctx,
        seed=int(seed),
        hardcore=False,
        full_version=True,
    )


def _strict_bootstrap_player_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "weapon_id": 1,
        "pos": {"x": 512.0, "y": 512.0},
        "health": 100.0,
        "ammo": 11.0,
        "experience": 0,
        "level": 1,
    }
    payload.update(overrides)
    return payload


def _strict_bootstrap_payload(*, tick_index: int = 0, player_count: int = 1) -> dict[str, object]:
    return {
        "tick_index": int(tick_index),
        "elapsed_ms": 0,
        "score_xp": 0,
        "perk_pending": 0,
        "perk": {
            "pending_count": 0,
            "choices_dirty": False,
            "choices": [],
            "player_nonzero_counts": [[] for _ in range(max(0, int(player_count)))],
        },
        "bonus_timers_ms": {},
        "players": [_strict_bootstrap_player_payload() for _ in range(max(0, int(player_count)))],
        "digital_move_enabled_by_player": [False for _ in range(max(0, int(player_count)))],
    }
