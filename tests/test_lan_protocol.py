from __future__ import annotations

import subprocess

from crimson.net import protocol
from crimson.net.protocol import Hello, Packet, PauseState, decode_packet, encode_packet


def test_packet_msgpack_round_trip() -> None:
    packet = Packet(
        seq=7,
        ack=3,
        reliable=True,
        message=Hello(
            build_id="build123",
            mode_id=1,
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


def test_protocol_constants_match_spec() -> None:
    assert protocol.PROTOCOL_VERSION == 1
    assert protocol.DEFAULT_PORT == 31993
    assert protocol.TICK_RATE == 60
    assert protocol.INPUT_DELAY_TICKS == 2
    assert protocol.MAX_PLAYERS == 4
    assert protocol.RELIABLE_RESEND_MS == 40
    assert protocol.LINK_TIMEOUT_MS == 1000
    assert protocol.INPUT_STALL_TIMEOUT_MS == 250
    assert protocol.STATE_HASH_PERIOD_TICKS == 120


def test_current_build_id_falls_back_to_package_version(monkeypatch) -> None:
    protocol.current_build_id.cache_clear()

    def _raise(*_args, **_kwargs):  # noqa: ANN001
        raise subprocess.CalledProcessError(returncode=1, cmd=["git"])

    monkeypatch.setattr(protocol.subprocess, "check_output", _raise)
    monkeypatch.setattr(protocol, "__version__", "9.9.9")

    assert protocol.current_build_id() == "9.9.9"


def test_decode_packet_rejects_invalid_blob() -> None:
    bad = encode_packet(Packet(seq=0, ack=0, reliable=False, message=PauseState(paused=False, reason="")))
    decoded = decode_packet(bad)
    assert isinstance(decoded.message, PauseState)
