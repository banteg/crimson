from __future__ import annotations

from typing import Literal

import msgspec

from ..game_modes import GameMode
from ..msgspec_types import NonNegativeInt, PlayerCount, PositiveInt
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from .lockstep_protocol import INPUT_DELAY_TICKS as LOCKSTEP_INPUT_DELAY_TICKS
from .lockstep_protocol import PROTOCOL_VERSION as LOCKSTEP_PROTOCOL_VERSION
from .lockstep_protocol import TICK_RATE as LOCKSTEP_TICK_RATE
from .lockstep_protocol import Hello, MatchStart, Welcome
from .relay_protocol import (
    INPUT_DELAY_TICKS as RELAY_INPUT_DELAY_TICKS,
)
from .relay_protocol import (
    ROLLBACK_MAX_TICKS,
    NetcodeMode,
    RelaySlot,
    RoomCreate,
    RoomStart,
    RoomState,
)
from .relay_protocol import (
    TICK_RATE as RELAY_TICK_RATE,
)
from .room_code import RoomCode


class LockstepSessionSettings(msgspec.Struct, frozen=True):
    mode_id: GameMode = GameMode.DEMO
    player_count: PlayerCount = 1
    quest_level: QuestLevel | None = None
    preserve_bugs: bool = False
    tick_rate: PositiveInt = LOCKSTEP_TICK_RATE
    input_delay_ticks: NonNegativeInt = LOCKSTEP_INPUT_DELAY_TICKS
    netcode_mode: Literal["lockstep"] = "lockstep"


class RelaySessionSettings(msgspec.Struct, frozen=True):
    mode_id: GameMode = GameMode.DEMO
    player_count: PlayerCount = 1
    quest_level: QuestLevel | None = None
    preserve_bugs: bool = False
    tick_rate: PositiveInt = RELAY_TICK_RATE
    input_delay_ticks: NonNegativeInt = RELAY_INPUT_DELAY_TICKS
    rollback_max_ticks: PositiveInt = ROLLBACK_MAX_TICKS
    netcode_mode: NetcodeMode = "rollback"


type SessionSettings = LockstepSessionSettings | RelaySessionSettings


def session_settings_from_hello(message: Hello) -> LockstepSessionSettings:
    return session_settings_for_lockstep(
        mode_id=message.mode_id,
        player_count=message.player_count,
        quest_level=message.quest_level,
        preserve_bugs=message.preserve_bugs,
        tick_rate=message.tick_rate,
        input_delay_ticks=message.input_delay_ticks,
    )


def session_settings_for_lockstep(
    *,
    mode_id: GameMode,
    player_count: int,
    quest_level: QuestLevel | None,
    preserve_bugs: bool,
    tick_rate: int = LOCKSTEP_TICK_RATE,
    input_delay_ticks: int = LOCKSTEP_INPUT_DELAY_TICKS,
) -> LockstepSessionSettings:
    player_count = max(1, min(4, player_count))
    tick_rate = max(1, tick_rate)
    input_delay_ticks = max(0, input_delay_ticks)
    return LockstepSessionSettings(
        mode_id=mode_id,
        player_count=player_count,
        quest_level=quest_level,
        preserve_bugs=preserve_bugs,
        tick_rate=tick_rate,
        input_delay_ticks=input_delay_ticks,
    )


def session_settings_from_welcome(message: Welcome) -> LockstepSessionSettings:
    return session_settings_for_lockstep(
        mode_id=message.mode_id,
        player_count=message.player_count,
        quest_level=message.quest_level,
        preserve_bugs=message.preserve_bugs,
        tick_rate=message.tick_rate,
        input_delay_ticks=message.input_delay_ticks,
    )


def welcome_from_session_settings(
    settings: LockstepSessionSettings,
    *,
    accepted: bool,
    reason: str = "",
    session_id: str = "",
    protocol_version: int = LOCKSTEP_PROTOCOL_VERSION,
    build_id: str = "",
    slot_index: int = -1,
    host_slot_index: int = 0,
    seed: int = 0,
    started: bool = False,
) -> Welcome:
    return Welcome(
        accepted=accepted,
        reason=reason,
        session_id=session_id,
        protocol_version=protocol_version,
        build_id=build_id,
        mode_id=settings.mode_id,
        player_count=settings.player_count,
        slot_index=slot_index,
        host_slot_index=host_slot_index,
        tick_rate=settings.tick_rate,
        input_delay_ticks=settings.input_delay_ticks,
        seed=seed,
        quest_level=settings.quest_level,
        preserve_bugs=settings.preserve_bugs,
        started=started,
    )


def session_settings_from_match_start(
    message: MatchStart,
    *,
    tick_rate: int = LOCKSTEP_TICK_RATE,
    input_delay_ticks: int = LOCKSTEP_INPUT_DELAY_TICKS,
) -> LockstepSessionSettings:
    return session_settings_for_lockstep(
        mode_id=message.mode_id,
        player_count=message.player_count,
        quest_level=message.quest_level,
        preserve_bugs=message.preserve_bugs,
        tick_rate=tick_rate,
        input_delay_ticks=input_delay_ticks,
    )


def match_start_from_session_settings(
    settings: LockstepSessionSettings,
    *,
    session_id: str,
    seed: int,
    start_tick: int = 0,
    status: GameStatusData | None = None,
) -> MatchStart:
    return MatchStart(
        session_id=session_id,
        mode_id=settings.mode_id,
        player_count=settings.player_count,
        seed=seed,
        start_tick=start_tick,
        quest_level=settings.quest_level,
        preserve_bugs=settings.preserve_bugs,
        status=status,
    )


def session_settings_for_relay(
    *,
    mode_id: GameMode,
    player_count: int,
    quest_level: QuestLevel | None,
    preserve_bugs: bool,
    tick_rate: int = RELAY_TICK_RATE,
    input_delay_ticks: int = RELAY_INPUT_DELAY_TICKS,
    rollback_max_ticks: int = ROLLBACK_MAX_TICKS,
    netcode_mode: NetcodeMode = "rollback",
) -> RelaySessionSettings:
    player_count = max(1, min(4, player_count))
    tick_rate = max(1, tick_rate)
    input_delay_ticks = max(0, input_delay_ticks)
    rollback_max_ticks = max(1, rollback_max_ticks)
    return RelaySessionSettings(
        mode_id=mode_id,
        player_count=player_count,
        quest_level=quest_level,
        preserve_bugs=preserve_bugs,
        tick_rate=tick_rate,
        input_delay_ticks=input_delay_ticks,
        rollback_max_ticks=rollback_max_ticks,
        netcode_mode=netcode_mode,
    )


def session_settings_from_room_create(message: RoomCreate) -> RelaySessionSettings:
    return session_settings_for_relay(
        mode_id=message.mode_id,
        player_count=message.player_count,
        quest_level=message.quest_level,
        preserve_bugs=message.preserve_bugs,
        tick_rate=message.tick_rate,
        input_delay_ticks=message.input_delay_ticks,
        rollback_max_ticks=message.rollback_max_ticks,
        netcode_mode=message.netcode_mode,
    )


def hello_from_session_settings(
    settings: LockstepSessionSettings,
    *,
    protocol_version: int,
    build_id: str,
    host: bool,
) -> Hello:
    return Hello(
        protocol_version=protocol_version,
        build_id=build_id,
        mode_id=settings.mode_id,
        player_count=settings.player_count,
        tick_rate=settings.tick_rate,
        input_delay_ticks=settings.input_delay_ticks,
        quest_level=settings.quest_level,
        preserve_bugs=settings.preserve_bugs,
        host=host,
    )


def room_create_from_session_settings(
    settings: RelaySessionSettings,
    *,
    status: GameStatusData | None = None,
) -> RoomCreate:
    return RoomCreate(
        mode_id=settings.mode_id,
        player_count=settings.player_count,
        quest_level=settings.quest_level,
        preserve_bugs=settings.preserve_bugs,
        tick_rate=settings.tick_rate,
        input_delay_ticks=settings.input_delay_ticks,
        rollback_max_ticks=settings.rollback_max_ticks,
        netcode_mode=settings.netcode_mode,
        status=status,
    )


def room_state_from_session_settings(
    settings: RelaySessionSettings,
    *,
    room_code: RoomCode,
    session_id: str,
    slots: list[RelaySlot],
    all_ready: bool,
    started: bool,
) -> RoomState:
    return RoomState(
        room_code=room_code,
        session_id=session_id,
        mode_id=settings.mode_id,
        player_count=settings.player_count,
        quest_level=settings.quest_level,
        preserve_bugs=settings.preserve_bugs,
        tick_rate=settings.tick_rate,
        input_delay_ticks=settings.input_delay_ticks,
        rollback_max_ticks=settings.rollback_max_ticks,
        netcode_mode=settings.netcode_mode,
        slots=slots,
        all_ready=all_ready,
        started=started,
    )


def room_start_from_session_settings(
    settings: RelaySessionSettings,
    *,
    room_code: RoomCode,
    session_id: str,
    seed: int,
    start_tick: int,
    slot_index: int,
    host_slot_index: int,
    reconnect_token: str,
    status: GameStatusData | None = None,
) -> RoomStart:
    return RoomStart(
        room_code=room_code,
        session_id=session_id,
        seed=seed,
        start_tick=start_tick,
        mode_id=settings.mode_id,
        player_count=settings.player_count,
        quest_level=settings.quest_level,
        preserve_bugs=settings.preserve_bugs,
        tick_rate=settings.tick_rate,
        input_delay_ticks=settings.input_delay_ticks,
        rollback_max_ticks=settings.rollback_max_ticks,
        netcode_mode=settings.netcode_mode,
        slot_index=slot_index,
        host_slot_index=host_slot_index,
        reconnect_token=reconnect_token,
        status=status,
    )
