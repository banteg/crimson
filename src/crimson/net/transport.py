from __future__ import annotations

import socket

import msgspec

from .protocol import Packet, decode_packet, encode_packet

PeerAddr = tuple[str, int]


class UdpTransport(msgspec.Struct):
    bind_host: str
    bind_port: int
    recv_buffer_size: int = 65536
    _sock: socket.socket | None = None

    @property
    def bound_port(self) -> int:
        sock = self._sock
        if sock is None:
            return int(self.bind_port)
        return int(sock.getsockname()[1])

    def open(self) -> None:
        if self._sock is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind((str(self.bind_host), int(self.bind_port)))
        self._sock = sock

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            return

    def send_packet(self, addr: PeerAddr, packet: Packet) -> None:
        sock = self._sock
        if sock is None:
            raise RuntimeError("transport is not open")
        blob = encode_packet(packet)
        sock.sendto(blob, (str(addr[0]), int(addr[1])))

    def recv_packets(self, *, max_packets: int | None = None) -> list[tuple[PeerAddr, Packet]]:
        sock = self._sock
        if sock is None:
            return []
        out: list[tuple[PeerAddr, Packet]] = []
        cap = None if max_packets is None else max(0, int(max_packets))
        while True:
            if cap is not None and len(out) >= int(cap):
                break
            try:
                blob, raw_addr = sock.recvfrom(int(self.recv_buffer_size))
            except BlockingIOError:
                break
            except OSError:
                break
            addr: PeerAddr = (str(raw_addr[0]), int(raw_addr[1]))
            try:
                packet = decode_packet(blob)
            except (msgspec.DecodeError, msgspec.ValidationError):
                # Ignore malformed datagrams.
                continue
            out.append((addr, packet))
        return out
