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
    # Highest *contiguous* reliable sequence that has been received and delivered.
    _recv_highest_seq: int = 0
    _pending: dict[int, _PendingReliable] = field(default_factory=dict)
    # Out-of-order reliable packets (seq > _recv_highest_seq + 1).
    _recv_buffer: dict[int, Packet] = field(default_factory=dict)

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

    def ingest_packet(self, packet: Packet) -> tuple[list[NetMessage], bool]:
        """Return `(messages, is_duplicate_reliable_packet)`.

        Reliable delivery uses a cumulative ACK of the highest contiguous reliable
        sequence that has been received and delivered. Out-of-order packets are
        buffered and only delivered once gaps are filled.
        """
        self._apply_ack(int(packet.ack))
        if not bool(packet.reliable):
            return [packet.message], False

        seq = int(packet.seq)
        if seq <= 0:
            return [], False

        if seq <= int(self._recv_highest_seq):
            return [], True
        if seq in self._recv_buffer:
            return [], True

        self._recv_buffer[int(seq)] = packet

        delivered: list[NetMessage] = []
        next_seq = int(self._recv_highest_seq) + 1
        while next_seq in self._recv_buffer:
            next_packet = self._recv_buffer.pop(int(next_seq))
            delivered.append(next_packet.message)
            self._recv_highest_seq = int(next_seq)
            next_seq += 1

        return delivered, False

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
