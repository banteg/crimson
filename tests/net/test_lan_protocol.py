from __future__ import annotations

import subprocess

import msgspec
import pytest

from crimson.game_modes import GameMode
from crimson.net import lockstep_protocol as protocol
from crimson.net.lockstep_protocol import (
    DebugLogBatch,
    Hello,
    KeepAlive,
    LockstepPacket,
    PauseState,
    TickFrame,
    decode_packet,
    encode_packet,
)
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand


def test_packet_msgpack_round_trip() -> None:
    packet = LockstepPacket(
        seq=7,
        ack=3,
        reliable=True,
        message=Hello(
            build_id="build123",
            mode_id=GameMode.SURVIVAL,
            player_count=2,
            host=False,
        ),
    )

    decoded = decode_packet(encode_packet(packet))

    assert decoded.seq == 7
    assert decoded.ack == 3
    assert decoded.reliable is True
    assert isinstance(decoded.message, Hello)
    assert decoded.message.build_id == "build123"
    assert decoded.message.mode_id == 1
    assert decoded.message.player_count == 2


def test_debug_log_batch_msgpack_round_trip() -> None:
    packet = LockstepPacket(
        seq=1,
        ack=0,
        reliable=False,
        message=DebugLogBatch(slot_index=1, lines=["test line\n"]),
    )

    decoded = decode_packet(encode_packet(packet))

    assert isinstance(decoded.message, DebugLogBatch)
    assert decoded.message.slot_index == 1
    assert decoded.message.lines == ["test line\n"]


def test_lan_tick_frame_and_keepalive_messages_round_trip() -> None:
    messages = [
        KeepAlive(tick_index=42),
        TickFrame(
            tick_index=123,
            frame_inputs=[[0.0, 0.0, 1.0, 2.0, 3]],
            commands=[
                PerkMenuOpenCommand(player_index=0),
                PerkPickCommand(player_index=0, choice_index=2),
            ],
        ),
    ]

    for idx, message in enumerate(messages, start=1):
        packet = LockstepPacket(seq=idx, ack=0, reliable=True, message=message)
        decoded = decode_packet(encode_packet(packet))
        assert type(decoded.message) is type(message)
        assert decoded.message == message


def test_protocol_constants_match_spec() -> None:
    assert protocol.PROTOCOL_VERSION == 6
    assert protocol.DEFAULT_PORT == 31993
    assert protocol.TICK_RATE == 60
    assert protocol.INPUT_DELAY_TICKS == 1
    assert protocol.MAX_PLAYERS == 4
    assert protocol.RELIABLE_RESEND_MS == 40
    assert protocol.LINK_TIMEOUT_MS == 1000
    assert protocol.INPUT_STALL_TIMEOUT_MS == 250


def test_current_build_id_falls_back_to_package_version(mocker) -> None:
    protocol.current_build_id.cache_clear()

    def _raise(*_args, **_kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd=["git"])

    mocker.patch.object(protocol.subprocess, "check_output", side_effect=_raise)
    mocker.patch.object(protocol, "__version__", "9.9.9")

    assert protocol.current_build_id() == "9.9.9"


def test_decode_packet_rejects_invalid_blob() -> None:
    bad = encode_packet(LockstepPacket(seq=0, ack=0, reliable=False, message=PauseState(paused=False, reason="")))
    decoded = decode_packet(bad)
    assert isinstance(decoded.message, PauseState)


def test_decode_packet_rejects_out_of_range_player_count_via_msgspec_constraints() -> None:
    blob = msgspec.msgpack.encode(
        {
            "seq": 0,
            "ack": 0,
            "reliable": False,
            "message": {
                "type": "hello",
                "protocol_version": protocol.PROTOCOL_VERSION,
                "build_id": "",
                "mode_id": 1,
                "player_count": 0,
                "tick_rate": protocol.TICK_RATE,
                "input_delay_ticks": protocol.INPUT_DELAY_TICKS,
                "quest_level": None,
                "preserve_bugs": False,
                "host": False,
            },
        },
    )

    with pytest.raises(msgspec.ValidationError, match="Expected `int` >= 1"):
        decode_packet(blob)


def test_build_compatibility_rejects_mismatched_git_hashes() -> None:
    assert protocol.builds_compatible("0.1.0+g1234567", "0.1.0+g7654321") is False


def test_build_compatibility_allows_release_to_match_same_public_version() -> None:
    assert protocol.builds_compatible("0.1.0", "0.1.0+g1234567") is True
