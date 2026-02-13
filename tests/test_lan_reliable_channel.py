from __future__ import annotations

from crimson.net.protocol import PauseState, Ready
from crimson.net.reliable import ReliableLink


def test_reliable_packet_is_acked_and_removed() -> None:
    sender = ReliableLink(resend_ms=40)
    receiver = ReliableLink(resend_ms=40)

    packet = sender.build_packet(Ready(slot_index=1, ready=True), reliable=True, now_ms=1000)
    message, is_dup = receiver.ingest_packet(packet)
    assert is_dup is False
    assert isinstance(message, Ready)

    ack = receiver.build_packet(PauseState(paused=False, reason=""), reliable=False, now_ms=1001)
    sender.ingest_packet(ack)

    assert sender.poll_resends(now_ms=2000) == []


def test_duplicate_reliable_packet_is_dropped() -> None:
    receiver = ReliableLink(resend_ms=40)
    sender = ReliableLink(resend_ms=40)

    packet = sender.build_packet(Ready(slot_index=2, ready=True), reliable=True, now_ms=10)

    message0, dup0 = receiver.ingest_packet(packet)
    message1, dup1 = receiver.ingest_packet(packet)

    assert isinstance(message0, Ready)
    assert dup0 is False
    assert message1 is None
    assert dup1 is True


def test_reliable_packet_is_resent_after_timeout() -> None:
    sender = ReliableLink(resend_ms=40)
    sender.build_packet(Ready(slot_index=1, ready=True), reliable=True, now_ms=0)

    assert sender.poll_resends(now_ms=39) == []

    resent = sender.poll_resends(now_ms=40)
    assert len(resent) == 1
    assert resent[0].reliable is True
    assert resent[0].seq == 1
