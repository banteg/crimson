from __future__ import annotations

import os
import re
import select
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import TypeVar

from crimson.net.relay_protocol import (
    ClientHello,
    ClientWelcome,
    NetMessage,
    RbInputBatch,
    RbInputSample,
    RbResyncChunk,
    RbResyncCommit,
    RbResyncRequest,
    RelayPacket,
    RoomCreate,
    RoomJoin,
    RoomReady,
    RoomStart,
    RoomState,
    decode_packet,
    encode_packet,
)

MessageT = TypeVar("MessageT", bound=NetMessage)


class _RelayClient:
    def __init__(self, *, port: int) -> None:
        self._server_addr = ("127.0.0.1", int(port))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(2.0)
        self._seq = 0
        self._ack = 0

    def close(self) -> None:
        self._sock.close()

    def send(self, message: NetMessage, *, reliable: bool = True) -> None:
        seq = 0
        if bool(reliable):
            self._seq += 1
            seq = int(self._seq)
        self._sock.sendto(
            encode_packet(RelayPacket(seq=seq, ack=int(self._ack), reliable=bool(reliable), message=message)),
            self._server_addr,
        )

    def recv(self, message_type: type[MessageT], *, timeout_s: float = 2.0) -> tuple[RelayPacket, MessageT]:
        deadline = time.monotonic() + float(timeout_s)
        while time.monotonic() < deadline:
            self._sock.settimeout(max(0.01, deadline - time.monotonic()))
            blob, _addr = self._sock.recvfrom(65536)
            packet = decode_packet(blob)
            if bool(packet.reliable) and int(packet.seq) > int(self._ack):
                self._ack = int(packet.seq)
            if isinstance(packet.message, message_type):
                return packet, packet.message
        raise AssertionError(f"timed out waiting for {message_type.__name__}")


def _start_zig_relay() -> tuple[subprocess.Popen[str], int]:
    repo_root = Path(__file__).resolve().parents[2]
    zig = shutil.which("zig")
    assert zig is not None
    proc = subprocess.Popen(
        [
            zig,
            "build",
            "relay-serve",
            "--",
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
            "--tick-ms",
            "1",
        ],
        cwd=repo_root / "crimson-zig",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        text=True,
    )
    return proc, _wait_for_relay_port(proc)


def _wait_for_relay_port(proc: subprocess.Popen[str], *, timeout_s: float = 10.0) -> int:
    assert proc.stderr is not None
    deadline = time.monotonic() + float(timeout_s)
    lines: list[str] = []
    while time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stderr], [], [], 0.1)
        if not ready:
            if proc.poll() is not None:
                break
            continue
        line = proc.stderr.readline()
        if not line:
            continue
        lines.append(line)
        match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
        if match is not None:
            return int(match.group(1))
    raise AssertionError(f"zig relay did not report a listening port; output={''.join(lines)!r}")


def test_zig_relay_server_accepts_python_client_hello() -> None:
    proc, port = _start_zig_relay()
    try:
        client = _RelayClient(port=port)
        try:
            client.send(ClientHello(build_id="0.1.0", peer_name="python"))
            decoded, welcome = client.recv(ClientWelcome)
        finally:
            client.close()

        assert decoded.reliable is True
        assert decoded.seq == 1
        assert welcome.accepted is True
        assert welcome.protocol_version == ClientHello().protocol_version
        assert welcome.peer_id
    finally:
        _stop_relay(proc)


def test_zig_relay_server_runs_python_two_peer_room_flow() -> None:
    proc, port = _start_zig_relay()
    host = _RelayClient(port=port)
    guest = _RelayClient(port=port)
    try:
        host.send(ClientHello(build_id="0.1.0", peer_name="host"))
        _host_welcome_packet, host_welcome = host.recv(ClientWelcome)
        assert host_welcome.accepted is True

        host.send(RoomCreate(player_count=2))
        _host_state_packet, host_state = host.recv(RoomState)
        assert host_state.room_code
        assert host_state.player_count == 2
        assert len(host_state.slots) == 2
        assert host_state.slots[0].connected is True
        assert host_state.slots[0].ready is True

        guest.send(ClientHello(build_id="0.1.0", peer_name="guest"))
        _guest_welcome_packet, guest_welcome = guest.recv(ClientWelcome)
        assert guest_welcome.accepted is True
        guest.send(RoomJoin(room_code=host_state.room_code))

        _host_join_state_packet, host_join_state = host.recv(RoomState)
        _guest_join_state_packet, guest_join_state = guest.recv(RoomState)
        assert [slot.connected for slot in host_join_state.slots] == [True, True]
        assert [slot.connected for slot in guest_join_state.slots] == [True, True]
        assert guest_join_state.started is False

        guest.send(RoomReady(slot_index=1, ready=True))
        _host_start_packet, host_start = host.recv(RoomStart)
        _guest_start_packet, guest_start = guest.recv(RoomStart)
        assert host_start.room_code == host_state.room_code
        assert guest_start.room_code == host_state.room_code
        assert host_start.slot_index == 0
        assert guest_start.slot_index == 1
        assert host_start.netcode_mode == "rollback"

        guest.send(
            RbInputBatch(
                slot_index=1,
                samples=[RbInputSample(tick_index=11, packed_input=[1.0, 0.0, 2.0, 3.0, 4])],
            ),
            reliable=False,
        )
        host_input_packet, host_input = host.recv(RbInputBatch)
        assert host_input_packet.reliable is False
        assert host_input.slot_index == 1
        assert host_input.samples[0].tick_index == 11
        assert host_input.samples[0].packed_input == [1.0, 0.0, 2.0, 3.0, 4]

        guest.send(RbResyncRequest(request_id="rq3", from_tick=20, reason="overflow", requested_by_slot=1))
        _host_resync_request_packet, host_resync_request = host.recv(RbResyncRequest)
        assert host_resync_request.request_id == "rq3"
        assert host_resync_request.requested_by_slot == 1

        host.send(RbResyncChunk(request_id="rq3", chunk_index=0, payload=b"abc"))
        host.send(RbResyncCommit(request_id="rq3", snapshot_tick=20))
        _guest_resync_chunk_packet, guest_resync_chunk = guest.recv(RbResyncChunk)
        _guest_resync_commit_packet, guest_resync_commit = guest.recv(RbResyncCommit)
        assert guest_resync_chunk.payload == b"abc"
        assert guest_resync_commit.request_id == "rq3"
    finally:
        host.close()
        guest.close()
        _stop_relay(proc)


def _stop_relay(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5.0)
