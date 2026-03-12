from __future__ import annotations

from ..game_modes import GameMode
from ..net.lockstep_protocol import INPUT_DELAY_TICKS as LOCKSTEP_INPUT_DELAY_TICKS
from ..net.session_settings import LockstepSessionSettings, session_settings_for_lockstep
from .types import ReplayHeader, ReplayStatusSnapshot


def session_settings_from_replay_header(
    header: ReplayHeader,
    *,
    input_delay_ticks: int = LOCKSTEP_INPUT_DELAY_TICKS,
) -> LockstepSessionSettings:
    return session_settings_for_lockstep(
        mode_id=header.game_mode_id,
        player_count=header.player_count,
        quest_level=header.quest_level,
        preserve_bugs=header.preserve_bugs,
        tick_rate=header.tick_rate,
        input_delay_ticks=input_delay_ticks,
    )


def replay_header_from_session_settings(
    settings: LockstepSessionSettings,
    *,
    seed: int,
    quest_fail_retry_count: int = 0,
    hardcore: bool = False,
    detail_preset: int = 5,
    gore_disabled: int = 0,
    world_size: float = 1024.0,
    status: ReplayStatusSnapshot | None = None,
) -> ReplayHeader:
    mode_raw = settings.mode_id
    try:
        game_mode_id = mode_raw if isinstance(mode_raw, GameMode) else GameMode(int(mode_raw))
    except ValueError as exc:
        raise ValueError(f"unsupported replay game_mode_id={mode_raw}") from exc
    quest_level = settings.quest_level
    if game_mode_id == GameMode.QUESTS and quest_level is None:
        raise ValueError("quest replays require quest_level")
    if game_mode_id == GameMode.TUTORIAL and settings.player_count != 1:
        raise ValueError("tutorial replays require player_count == 1")

    return ReplayHeader(
        game_mode_id=game_mode_id,
        seed=seed,
        quest_level=quest_level,
        tick_rate=settings.tick_rate,
        quest_fail_retry_count=quest_fail_retry_count,
        hardcore=hardcore,
        preserve_bugs=settings.preserve_bugs,
        detail_preset=detail_preset,
        gore_disabled=gore_disabled,
        world_size=world_size,
        player_count=settings.player_count,
        status=ReplayStatusSnapshot() if status is None else status,
    )
