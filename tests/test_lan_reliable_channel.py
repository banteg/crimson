from __future__ import annotations

from crimson.net.protocol import PauseState, Ready
from crimson.net.reliable import ReliableLink


def test_reliable_packet_is_acked_and_removed() -> None:
    sender = ReliableLink(resend_ms=40)
    receiver = ReliableLink(resend_ms=40)

    packet = sender.build_packet(Ready(slot_index=1, ready=True), reliable=True, now_ms=1000)
    messages, is_dup = receiver.ingest_packet(packet)
    assert is_dup is False
    assert len(messages) == 1
    assert isinstance(messages[0], Ready)

    ack = receiver.build_packet(PauseState(paused=False, reason=""), reliable=False, now_ms=1001)
    sender.ingest_packet(ack)

    assert sender.poll_resends(now_ms=2000) == []


def test_duplicate_reliable_packet_is_dropped() -> None:
    receiver = ReliableLink(resend_ms=40)
    sender = ReliableLink(resend_ms=40)

    packet = sender.build_packet(Ready(slot_index=2, ready=True), reliable=True, now_ms=10)

    messages0, dup0 = receiver.ingest_packet(packet)
    messages1, dup1 = receiver.ingest_packet(packet)

    assert len(messages0) == 1
    assert isinstance(messages0[0], Ready)
    assert dup0 is False
    assert messages1 == []
    assert dup1 is True


def test_reliable_packet_is_resent_after_timeout() -> None:
    sender = ReliableLink(resend_ms=40)
    sender.build_packet(Ready(slot_index=1, ready=True), reliable=True, now_ms=0)

    assert sender.poll_resends(now_ms=39) == []

    resent = sender.poll_resends(now_ms=40)
    assert len(resent) == 1
    assert resent[0].reliable is True
    assert resent[0].seq == 1


def test_reliable_delivery_buffers_out_of_order_packets_and_acks_contiguously() -> None:
    sender = ReliableLink(resend_ms=40)
    receiver = ReliableLink(resend_ms=40)

    p1 = sender.build_packet(Ready(slot_index=1, ready=True), reliable=True, now_ms=0)
    p2 = sender.build_packet(Ready(slot_index=2, ready=True), reliable=True, now_ms=0)

    # Deliver seq=2 first: receiver should buffer it and not advance contiguous ACK.
    msgs2, dup2 = receiver.ingest_packet(p2)
    assert dup2 is False
    assert msgs2 == []
    assert receiver.recv_highest_seq == 0

    # Deliver seq=1: receiver can now deliver both 1 and 2 in order.
    msgs1, dup1 = receiver.ingest_packet(p1)
    assert dup1 is False
    assert [m.slot_index for m in msgs1 if isinstance(m, Ready)] == [1, 2]
    assert receiver.recv_highest_seq == 2
