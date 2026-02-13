from __future__ import annotations

from dataclasses import dataclass, field

from .protocol import RELIABLE_RESEND_MS, NetMessage, Packet


@dataclass(slots=True)
class _PendingReliable:
    packet: Packet
    sent_at_ms: int


@dataclass(slots=True)
class ReliableLink:
    """Per-peer reliability state (sequence, ack, resend, de-dup)."""

    resend_ms: int = RELIABLE_RESEND_MS
    _next_seq: int = 1
    _recv_highest_seq: int = 0
    _pending: dict[int, _PendingReliable] = field(default_factory=dict)
    _seen_reliable: set[int] = field(default_factory=set)

    @property
    def recv_highest_seq(self) -> int:
        return int(self._recv_highest_seq)

    def build_packet(self, message: NetMessage, *, reliable: bool, now_ms: int) -> Packet:
        seq = 0
        if reliable:
            seq = int(self._next_seq)
            self._next_seq += 1
        packet = Packet(
            seq=int(seq),
            ack=int(self._recv_highest_seq),
            reliable=bool(reliable),
            message=message,
        )
        if reliable:
            self._pending[int(seq)] = _PendingReliable(packet=packet, sent_at_ms=int(now_ms))
        return packet

    def ingest_packet(self, packet: Packet) -> tuple[NetMessage | None, bool]:
        """Return `(message, is_duplicate_reliable)`."""
        self._apply_ack(int(packet.ack))
        if not bool(packet.reliable):
            return packet.message, False

        seq = int(packet.seq)
        if seq <= 0:
            return None, False
        if seq in self._seen_reliable:
            # Already processed. Caller can still use outbound ack on next send.
            self._recv_highest_seq = max(int(self._recv_highest_seq), int(seq))
            return None, True

        self._seen_reliable.add(int(seq))
        self._recv_highest_seq = max(int(self._recv_highest_seq), int(seq))
        return packet.message, False

    def _apply_ack(self, ack: int) -> None:
        if int(ack) <= 0:
            return
        to_drop = [seq for seq in self._pending if int(seq) <= int(ack)]
        for seq in to_drop:
            self._pending.pop(int(seq), None)

    def poll_resends(self, *, now_ms: int) -> list[Packet]:
        out: list[Packet] = []
        for seq, pending in list(self._pending.items()):
            if int(now_ms) - int(pending.sent_at_ms) < int(self.resend_ms):
                continue
            # Re-send packet with up-to-date ACK.
            refreshed = Packet(
                seq=int(pending.packet.seq),
                ack=int(self._recv_highest_seq),
                reliable=True,
                message=pending.packet.message,
            )
            self._pending[int(seq)] = _PendingReliable(packet=refreshed, sent_at_ms=int(now_ms))
            out.append(refreshed)
        return out
