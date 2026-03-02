from __future__ import annotations

from crimson.net.relay_protocol import RelaySlot, StatusSnapshot
from crimson.net.session_settings import (
    hello_from_session_settings,
    room_create_from_session_settings,
    room_start_from_session_settings,
    room_state_from_session_settings,
    session_settings_for_lockstep,
    session_settings_for_relay,
    session_settings_from_room_create,
)


def test_lockstep_session_settings_build_hello() -> None:
    settings = session_settings_for_lockstep(
        mode_id=3,
        player_count=9,
        quest_level="q_2_3",
        preserve_bugs=True,
        tick_rate=0,
        input_delay_ticks=-5,
    )
    assert settings.player_count == 4
    assert settings.tick_rate == 1
    assert settings.input_delay_ticks == 0
    assert settings.netcode_mode == "lockstep"
    assert settings.rollback_max_ticks == 0

    hello = hello_from_session_settings(settings, protocol_version=7, build_id="dev+g1234", host=False)
    assert hello.protocol_version == 7
    assert hello.build_id == "dev+g1234"
    assert hello.mode_id == 3
    assert hello.player_count == 4
    assert hello.quest_level == "q_2_3"
    assert hello.preserve_bugs is True
    assert hello.tick_rate == 1
    assert hello.input_delay_ticks == 0
    assert hello.host is False


def test_relay_session_settings_roundtrip_from_room_create() -> None:
    settings = session_settings_for_relay(
        mode_id=2,
        player_count=0,
        quest_level="",
        preserve_bugs=False,
        tick_rate=0,
        input_delay_ticks=-1,
        rollback_max_ticks=0,
        netcode_mode="rollback",
    )
    assert settings.player_count == 1
    assert settings.tick_rate == 1
    assert settings.input_delay_ticks == 0
    assert settings.rollback_max_ticks == 1

    snapshot = StatusSnapshot(quest_unlock_index=11, quest_unlock_index_full=22)
    create = room_create_from_session_settings(settings, status_snapshot=snapshot)
    restored = session_settings_from_room_create(create)
    assert restored == settings
    assert create.status_snapshot == snapshot


def test_relay_session_settings_build_room_state_and_start() -> None:
    settings = session_settings_for_relay(
        mode_id=1,
        player_count=2,
        quest_level="q_1_1",
        preserve_bugs=True,
        tick_rate=60,
        input_delay_ticks=2,
        rollback_max_ticks=6,
        netcode_mode="lockstep",
    )
    slots = [
        RelaySlot(slot_index=0, connected=True, ready=True, is_host=True, peer_name="host"),
        RelaySlot(slot_index=1, connected=True, ready=False, is_host=False, peer_name="guest"),
    ]
    state = room_state_from_session_settings(
        settings,
        room_code="ABCD",
        session_id="session42",
        slots=slots,
        all_ready=False,
        started=False,
    )
    assert state.mode_id == 1
    assert state.player_count == 2
    assert state.quest_level == "q_1_1"
    assert state.netcode_mode == "lockstep"
    assert state.rollback_max_ticks == 6
    assert len(state.slots) == 2

    start = room_start_from_session_settings(
        settings,
        room_code="ABCD",
        session_id="session42",
        seed=123,
        start_tick=5,
        slot_index=1,
        host_slot_index=0,
        reconnect_token="token123",
        status_snapshot=StatusSnapshot(),
    )
    assert start.mode_id == 1
    assert start.player_count == 2
    assert start.slot_index == 1
    assert start.host_slot_index == 0
    assert start.netcode_mode == "lockstep"
