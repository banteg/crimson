from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.replay.types import current_replay_game_version
from crimson.sim.input import PlayerInput
from grim.geom import Vec2


def _blank_survival_replay(
    *, ticks: int, seed: int = 0xBEEF, game_version: str | None = None,
) -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=(str(current_replay_game_version()) if game_version is None else str(game_version)),
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _blank_rush_replay(
    *, ticks: int, seed: int = 0xBEEF, game_version: str | None = None,
) -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.RUSH),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=(str(current_replay_game_version()) if game_version is None else str(game_version)),
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _blank_quest_replay(
    *, ticks: int, seed: int = 101, game_version: str | None = None,
) -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.QUESTS),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=(str(current_replay_game_version()) if game_version is None else str(game_version)),
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
