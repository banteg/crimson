from __future__ import annotations

from ..game_modes import GameMode
from ..net.lockstep_protocol import INPUT_DELAY_TICKS as LOCKSTEP_INPUT_DELAY_TICKS
from ..net.session_settings import LockstepSessionSettings, session_settings_for_lockstep
from .types import BootstrapKind, ReplayHeader, ReplayStatusSnapshot


def session_settings_from_replay_header(
    header: ReplayHeader,
    *,
    input_delay_ticks: int = LOCKSTEP_INPUT_DELAY_TICKS,
) -> LockstepSessionSettings:
    return session_settings_for_lockstep(
        mode_id=int(header.game_mode_id),
        player_count=int(header.player_count),
        quest_level=str(header.quest_level),
        preserve_bugs=bool(header.preserve_bugs),
        tick_rate=int(header.tick_rate),
        input_delay_ticks=int(input_delay_ticks),
    )


def replay_header_from_session_settings(
    settings: LockstepSessionSettings,
    *,
    seed: int,
    bootstrap_kind: BootstrapKind = "none",
    bootstrap_seed: int = 0,
    difficulty_level: int = 0,
    hardcore: bool = False,
    detail_preset: int = 5,
    gore_disabled: int = 0,
    world_size: float = 1024.0,
    status: ReplayStatusSnapshot | None = None,
) -> ReplayHeader:
    mode_raw = int(settings.mode_id)
    try:
        game_mode_id = GameMode(mode_raw)
    except ValueError as exc:
        raise ValueError(f"unsupported replay game_mode_id={mode_raw}") from exc

    return ReplayHeader(
        game_mode_id=game_mode_id,
        seed=int(seed),
        quest_level=str(settings.quest_level),
        bootstrap_kind=bootstrap_kind,
        bootstrap_seed=int(bootstrap_seed),
        tick_rate=int(settings.tick_rate),
        difficulty_level=int(difficulty_level),
        hardcore=bool(hardcore),
        preserve_bugs=bool(settings.preserve_bugs),
        detail_preset=int(detail_preset),
        gore_disabled=int(gore_disabled),
        world_size=float(world_size),
        player_count=int(settings.player_count),
        status=ReplayStatusSnapshot() if status is None else status,
    )
