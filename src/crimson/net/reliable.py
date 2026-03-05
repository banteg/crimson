from __future__ import annotations

import msgspec

from .lockstep_protocol import RELIABLE_RESEND_MS, LockstepPacket, NetMessage


class _LockstepPendingReliable(msgspec.Struct):
    packet: LockstepPacket
    sent_at_ms: int


class ReliableLink(msgspec.Struct):
    """Per-peer reliability state (sequence, ack, resend, de-dup)."""

    resend_ms: int = RELIABLE_RESEND_MS
    _next_seq: int = 1
    # Highest *contiguous* reliable sequence that has been received and delivered.
    _recv_highest_seq: int = 0
    _pending: dict[int, _LockstepPendingReliable] = msgspec.field(default_factory=dict)
    # Out-of-order reliable packets (seq > _recv_highest_seq + 1).
    _recv_buffer: dict[int, LockstepPacket] = msgspec.field(default_factory=dict)
    # Very rough RTT estimate based on ACK turnaround. Useful for debugging only.
    _rtt_last_ms: int = 0
    _rtt_ewma_ms: float = 0.0
    _resend_count: int = 0

    @property
    def recv_highest_seq(self) -> int:
        return int(self._recv_highest_seq)

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def rtt_last_ms(self) -> int:
        return int(self._rtt_last_ms)

    @property
    def rtt_ewma_ms(self) -> float:
        return float(self._rtt_ewma_ms)

    @property
    def resend_count(self) -> int:
        return int(self._resend_count)

    def prime_recv_seq(self, seq: int) -> None:
        """Record a reliable seq as already delivered.

        Used when a trusted message is handled out-of-band (for example an
        initial handshake packet) so ACK progression remains contiguous.
        """
        value = int(seq)
        if value <= int(self._recv_highest_seq):
            return
        self._recv_highest_seq = int(value)

    def build_packet(self, message: NetMessage, *, reliable: bool, now_ms: int) -> LockstepPacket:
        seq = 0
        if reliable:
            seq = int(self._next_seq)
            self._next_seq += 1
        packet = LockstepPacket(
            seq=int(seq),
            ack=int(self._recv_highest_seq),
            reliable=bool(reliable),
            message=message,
        )
        if reliable:
            self._pending[int(seq)] = _LockstepPendingReliable(packet=packet, sent_at_ms=int(now_ms))
        return packet

    def ingest_packet(self, packet: LockstepPacket, *, now_ms: int) -> tuple[list[NetMessage], bool]:
        """Return `(messages, is_duplicate_reliable_packet)`.

        Reliable delivery uses a cumulative ACK of the highest contiguous reliable
        sequence that has been received and delivered. Out-of-order packets are
        buffered and only delivered once gaps are filled.
        """
        self._apply_ack(int(packet.ack), now_ms=int(now_ms))
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

    def _apply_ack(self, ack: int, *, now_ms: int) -> None:
        if int(ack) <= 0:
            return
        to_drop = [seq for seq in self._pending if int(seq) <= int(ack)]
        if not to_drop:
            return

        # RTT sample: use the newest pending seq that got ACKed in this packet.
        newest_seq = max(int(seq) for seq in to_drop)
        pending = self._pending.get(int(newest_seq))
        if pending is not None:
            sample_ms = max(0, int(now_ms) - int(pending.sent_at_ms))
            self._rtt_last_ms = int(sample_ms)
            if self._rtt_ewma_ms <= 0.0:
                self._rtt_ewma_ms = float(sample_ms)
            else:
                # Heavily smoothed; this is for HUD/debug, not congestion control.
                self._rtt_ewma_ms = float(self._rtt_ewma_ms * 0.9 + float(sample_ms) * 0.1)

        for seq in to_drop:
            self._pending.pop(int(seq), None)

    def poll_resends(self, *, now_ms: int) -> list[LockstepPacket]:
        out: list[LockstepPacket] = []
        for seq, pending in list(self._pending.items()):
            if int(now_ms) - int(pending.sent_at_ms) < int(self.resend_ms):
                continue
            # Re-send packet with up-to-date ACK.
            refreshed = LockstepPacket(
                seq=int(pending.packet.seq),
                ack=int(self._recv_highest_seq),
                reliable=True,
                message=pending.packet.message,
            )
            self._pending[int(seq)] = _LockstepPendingReliable(packet=refreshed, sent_at_ms=int(now_ms))
            out.append(refreshed)
            self._resend_count += 1
        return out
