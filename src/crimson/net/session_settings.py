from __future__ import annotations

import msgspec

from .lockstep_protocol import INPUT_DELAY_TICKS as LOCKSTEP_INPUT_DELAY_TICKS
from .lockstep_protocol import TICK_RATE as LOCKSTEP_TICK_RATE
from .lockstep_protocol import Hello
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
    StatusSnapshot,
)
from .relay_protocol import (
    TICK_RATE as RELAY_TICK_RATE,
)


class SessionSettings(msgspec.Struct, frozen=True):
    mode_id: int = 0
    player_count: int = 1
    quest_level: str = ""
    preserve_bugs: bool = False
    tick_rate: int = LOCKSTEP_TICK_RATE
    input_delay_ticks: int = LOCKSTEP_INPUT_DELAY_TICKS
    netcode_mode: NetcodeMode = "lockstep"
    rollback_max_ticks: int = 0


def session_settings_for_lockstep(
    *,
    mode_id: int,
    player_count: int,
    quest_level: str,
    preserve_bugs: bool,
    tick_rate: int = LOCKSTEP_TICK_RATE,
    input_delay_ticks: int = LOCKSTEP_INPUT_DELAY_TICKS,
) -> SessionSettings:
    return SessionSettings(
        mode_id=int(mode_id),
        player_count=max(1, min(4, int(player_count))),
        quest_level=str(quest_level or ""),
        preserve_bugs=bool(preserve_bugs),
        tick_rate=max(1, int(tick_rate)),
        input_delay_ticks=max(0, int(input_delay_ticks)),
        netcode_mode="lockstep",
        rollback_max_ticks=0,
    )


def session_settings_for_relay(
    *,
    mode_id: int,
    player_count: int,
    quest_level: str,
    preserve_bugs: bool,
    tick_rate: int = RELAY_TICK_RATE,
    input_delay_ticks: int = RELAY_INPUT_DELAY_TICKS,
    rollback_max_ticks: int = ROLLBACK_MAX_TICKS,
    netcode_mode: NetcodeMode = "rollback",
) -> SessionSettings:
    mode_raw = str(netcode_mode)
    mode: NetcodeMode = "lockstep" if mode_raw == "lockstep" else "rollback"
    return SessionSettings(
        mode_id=int(mode_id),
        player_count=max(1, min(4, int(player_count))),
        quest_level=str(quest_level or ""),
        preserve_bugs=bool(preserve_bugs),
        tick_rate=max(1, int(tick_rate)),
        input_delay_ticks=max(0, int(input_delay_ticks)),
        rollback_max_ticks=max(1, int(rollback_max_ticks)),
        netcode_mode=mode,
    )


def session_settings_from_room_create(message: RoomCreate) -> SessionSettings:
    return session_settings_for_relay(
        mode_id=int(message.mode_id),
        player_count=int(message.player_count),
        quest_level=str(message.quest_level),
        preserve_bugs=bool(message.preserve_bugs),
        tick_rate=int(message.tick_rate),
        input_delay_ticks=int(message.input_delay_ticks),
        rollback_max_ticks=int(message.rollback_max_ticks),
        netcode_mode=message.netcode_mode,
    )


def hello_from_session_settings(
    settings: SessionSettings,
    *,
    protocol_version: int,
    build_id: str,
    host: bool,
) -> Hello:
    return Hello(
        protocol_version=int(protocol_version),
        build_id=str(build_id),
        mode_id=int(settings.mode_id),
        player_count=int(settings.player_count),
        tick_rate=int(settings.tick_rate),
        input_delay_ticks=int(settings.input_delay_ticks),
        quest_level=str(settings.quest_level),
        preserve_bugs=bool(settings.preserve_bugs),
        host=bool(host),
    )


def room_create_from_session_settings(
    settings: SessionSettings,
    *,
    status_snapshot: StatusSnapshot | None = None,
) -> RoomCreate:
    return RoomCreate(
        mode_id=int(settings.mode_id),
        player_count=int(settings.player_count),
        quest_level=str(settings.quest_level),
        preserve_bugs=bool(settings.preserve_bugs),
        tick_rate=int(settings.tick_rate),
        input_delay_ticks=int(settings.input_delay_ticks),
        rollback_max_ticks=max(1, int(settings.rollback_max_ticks)),
        netcode_mode=settings.netcode_mode,
        status_snapshot=status_snapshot,
    )


def room_state_from_session_settings(
    settings: SessionSettings,
    *,
    room_code: str,
    session_id: str,
    slots: list[RelaySlot],
    all_ready: bool,
    started: bool,
) -> RoomState:
    return RoomState(
        room_code=str(room_code),
        session_id=str(session_id),
        mode_id=int(settings.mode_id),
        player_count=int(settings.player_count),
        quest_level=str(settings.quest_level),
        preserve_bugs=bool(settings.preserve_bugs),
        tick_rate=int(settings.tick_rate),
        input_delay_ticks=int(settings.input_delay_ticks),
        rollback_max_ticks=max(1, int(settings.rollback_max_ticks)),
        netcode_mode=settings.netcode_mode,
        slots=slots,
        all_ready=bool(all_ready),
        started=bool(started),
    )


def room_start_from_session_settings(
    settings: SessionSettings,
    *,
    room_code: str,
    session_id: str,
    seed: int,
    start_tick: int,
    slot_index: int,
    host_slot_index: int,
    reconnect_token: str,
    status_snapshot: StatusSnapshot | None = None,
) -> RoomStart:
    return RoomStart(
        room_code=str(room_code),
        session_id=str(session_id),
        seed=int(seed),
        start_tick=int(start_tick),
        mode_id=int(settings.mode_id),
        player_count=int(settings.player_count),
        quest_level=str(settings.quest_level),
        preserve_bugs=bool(settings.preserve_bugs),
        tick_rate=int(settings.tick_rate),
        input_delay_ticks=int(settings.input_delay_ticks),
        rollback_max_ticks=max(1, int(settings.rollback_max_ticks)),
        netcode_mode=settings.netcode_mode,
        slot_index=int(slot_index),
        host_slot_index=int(host_slot_index),
        reconnect_token=str(reconnect_token),
        status_snapshot=status_snapshot,
    )
