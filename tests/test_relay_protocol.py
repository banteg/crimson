from __future__ import annotations

from crimson.net.relay_protocol import (
    DEFAULT_PORT,
    INPUT_DELAY_TICKS,
    PROTOCOL_VERSION,
    RECONNECT_TIMEOUT_MS,
    ROLLBACK_MAX_TICKS,
    ClientHello,
    LegacyLockstepControl,
    Packet,
    RelayError,
    RbInputBatch,
    RbInputSample,
    RoomCreate,
    decode_packet,
    encode_packet,
)


def test_relay_packet_round_trip_for_control_message() -> None:
    packet = Packet(
        seq=7,
        ack=3,
        reliable=True,
        message=RoomCreate(
            mode_id=2,
            player_count=3,
            quest_level="",
            preserve_bugs=False,
            rollback_max_ticks=8,
            netcode_mode="rollback",
        ),
    )

    decoded = decode_packet(encode_packet(packet))

    assert decoded.seq == 7
    assert decoded.ack == 3
    assert decoded.reliable is True
    assert isinstance(decoded.message, RoomCreate)
    assert decoded.message.mode_id == 2
    assert decoded.message.player_count == 3


def test_relay_packet_round_trip_for_rollback_input_batch() -> None:
    packet = Packet(
        seq=0,
        ack=0,
        reliable=False,
        message=RbInputBatch(
            slot_index=1,
            samples=[RbInputSample(tick_index=11, packed_input=[1.0, 0.0, [2.0, 3.0], 4])],
        ),
    )

    decoded = decode_packet(encode_packet(packet))

    assert isinstance(decoded.message, RbInputBatch)
    assert decoded.message.slot_index == 1
    assert decoded.message.samples[0].tick_index == 11


def test_relay_packet_round_trip_for_legacy_tunnel_message() -> None:
    packet = Packet(
        seq=1,
        ack=0,
        reliable=True,
        message=LegacyLockstepControl(payload=b"legacy"),
    )

    decoded = decode_packet(encode_packet(packet))

    assert isinstance(decoded.message, LegacyLockstepControl)
    assert decoded.message.payload == b"legacy"


def test_relay_protocol_constants_match_v4_spec() -> None:
    assert PROTOCOL_VERSION == 4
    assert DEFAULT_PORT == 31993
    assert INPUT_DELAY_TICKS == 1
    assert ROLLBACK_MAX_TICKS == 8
    assert RECONNECT_TIMEOUT_MS == 15_000


def test_relay_error_round_trip() -> None:
    packet = Packet(seq=1, ack=0, reliable=True, message=RelayError(reason="room_not_found"))

    decoded = decode_packet(encode_packet(packet))

    assert isinstance(decoded.message, RelayError)
    assert decoded.message.reason == "room_not_found"


def test_client_hello_round_trip() -> None:
    packet = Packet(
        seq=1,
        ack=0,
        reliable=True,
        message=ClientHello(protocol_version=PROTOCOL_VERSION, build_id="dev", peer_name="p0"),
    )

    decoded = decode_packet(encode_packet(packet))

    assert isinstance(decoded.message, ClientHello)
    assert decoded.message.build_id == "dev"
