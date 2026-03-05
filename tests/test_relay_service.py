from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from crimson.net.relay_protocol import (
    PROTOCOL_VERSION,
    ROOM_CODE_LENGTH,
    ClientHello,
    ClientWelcome,
    RbResyncBegin,
    RbResyncChunk,
    RbResyncCommit,
    RbResyncRequest,
    RelayError,
    RoomCreate,
    RoomJoin,
    RoomReady,
    RoomStart,
    RoomState,
)
from crimson.net.relay_service import RelayServer, RelayServerConfig


def _packet_calls(send_packet: MagicMock) -> list[tuple[tuple[str, int], Any]]:
    packets: list[tuple[tuple[str, int], Any]] = []
    for call in send_packet.call_args_list:
        if len(call.args) == 3:
            packets.append((call.args[1], call.args[2]))
            continue
        packets.append((call.args[0], call.args[1]))
    return packets


def _patch_send_capture(mocker, server: RelayServer) -> MagicMock:
    return mocker.patch.object(type(server.transport), "send_packet")


def _hello_peer(server: RelayServer, *, addr: tuple[str, int], build_id: str, now_ms: int) -> Any:
    server._handle_client_hello(
        addr=addr,
        message=ClientHello(
            protocol_version=int(PROTOCOL_VERSION),
            build_id=str(build_id),
            peer_name="",
        ),
        now_ms=int(now_ms),
    )
    return server._peers_by_addr[addr]


def _start_two_peer_room(server: RelayServer, *, now_ms: int) -> tuple[Any, Any, str]:
    host_addr = ("127.0.0.1", 40001)
    join_addr = ("127.0.0.1", 40002)
    host_peer = _hello_peer(server, addr=host_addr, build_id="0.1.0", now_ms=int(now_ms))
    join_peer = _hello_peer(server, addr=join_addr, build_id="0.1.0", now_ms=int(now_ms) + 1)

    server._handle_message(
        peer=host_peer,
        message=RoomCreate(
            mode_id=1,
            player_count=2,
            quest_level="",
            preserve_bugs=False,
            netcode_mode="rollback",
        ),
        now_ms=int(now_ms) + 2,
    )
    room_code = str(host_peer.room_code)
    server._handle_message(
        peer=join_peer,
        message=RoomJoin(room_code=room_code, reconnect_token=""),
        now_ms=int(now_ms) + 3,
    )
    server._handle_message(
        peer=join_peer,
        message=RoomReady(slot_index=1, ready=True),
        now_ms=int(now_ms) + 4,
    )
    return host_peer, join_peer, room_code


def test_room_create_join_ready_start_flow(mocker) -> None:
    server = RelayServer(RelayServerConfig(bind_host="127.0.0.1", bind_port=0))
    send_packet = _patch_send_capture(mocker, server)

    host_addr = ("127.0.0.1", 40101)
    join_addr = ("127.0.0.1", 40102)

    host_peer = _hello_peer(server, addr=host_addr, build_id="0.1.0", now_ms=1000)
    sent = _packet_calls(send_packet)
    assert any(addr == host_addr and isinstance(packet.message, ClientWelcome) for addr, packet in sent)
    send_packet.reset_mock()

    server._handle_message(
        peer=host_peer,
        message=RoomCreate(
            mode_id=2,
            player_count=2,
            quest_level="",
            preserve_bugs=False,
            netcode_mode="rollback",
        ),
        now_ms=1001,
    )
    room_code = str(host_peer.room_code)
    assert room_code
    assert len(room_code) == int(ROOM_CODE_LENGTH)
    assert room_code.isalnum()
    assert room_code in server._rooms
    sent = _packet_calls(send_packet)
    assert any(isinstance(packet.message, RoomState) for _addr, packet in sent)
    send_packet.reset_mock()

    join_peer = _hello_peer(server, addr=join_addr, build_id="0.1.0", now_ms=1002)
    server._handle_message(
        peer=join_peer,
        message=RoomJoin(room_code=room_code, reconnect_token=""),
        now_ms=1003,
    )
    assert int(join_peer.slot_index) == 1
    assert str(join_peer.room_code) == room_code
    sent = _packet_calls(send_packet)
    assert any(isinstance(packet.message, RoomState) for _addr, packet in sent)
    send_packet.reset_mock()

    server._handle_message(
        peer=join_peer,
        message=RoomReady(slot_index=1, ready=True),
        now_ms=1004,
    )
    room = server._rooms[room_code]
    assert room.started is True
    sent = _packet_calls(send_packet)
    room_start_addrs = {addr for addr, packet in sent if isinstance(packet.message, RoomStart)}
    assert room_start_addrs == {host_addr, join_addr}


def test_reconnect_token_reclaims_slot_and_receives_room_start(mocker) -> None:
    server = RelayServer(RelayServerConfig(bind_host="127.0.0.1", bind_port=0))
    send_packet = _patch_send_capture(mocker, server)
    host_peer, join_peer, room_code = _start_two_peer_room(server, now_ms=2000)
    room = server._rooms[room_code]
    reconnect_token = str(room.slots[1].reconnect_token)
    assert reconnect_token

    server._disconnect_peer(peer=join_peer, reason="timeout", now_ms=2200)
    assert room.slots[1].connected is False
    assert server._room_by_reconnect[reconnect_token] == (room_code, 1)

    send_packet.reset_mock()
    new_addr = ("127.0.0.1", 40003)
    new_peer = _hello_peer(server, addr=new_addr, build_id="0.1.0", now_ms=2201)
    server._handle_message(
        peer=new_peer,
        message=RoomJoin(room_code="", reconnect_token=reconnect_token),
        now_ms=2202,
    )

    assert str(new_peer.room_code) == room_code
    assert int(new_peer.slot_index) == 1
    assert str(room.slots[1].peer_id) == str(new_peer.peer_id)
    sent = _packet_calls(send_packet)
    assert any(addr == new_addr and isinstance(packet.message, RoomStart) for addr, packet in sent)
    assert str(room.slots[0].peer_id) == str(host_peer.peer_id)


def test_protocol_mismatch_requires_v5(mocker) -> None:
    server = RelayServer(RelayServerConfig(bind_host="127.0.0.1", bind_port=0))
    send_packet = _patch_send_capture(mocker, server)

    server._handle_client_hello(
        addr=("127.0.0.1", 50901),
        message=ClientHello(protocol_version=4, build_id="0.1.0", peer_name=""),
        now_ms=1000,
    )

    sent = _packet_calls(send_packet)
    assert any(
        isinstance(packet.message, ClientWelcome)
        and packet.message.accepted is False
        and packet.message.reason == "protocol_mismatch_v5_required"
        for _addr, packet in sent
    )


def test_resync_sender_role_validation(mocker) -> None:
    server = RelayServer(RelayServerConfig(bind_host="127.0.0.1", bind_port=0))
    send_packet = _patch_send_capture(mocker, server)
    host_peer, join_peer, _room_code = _start_two_peer_room(server, now_ms=6000)

    send_packet.reset_mock()
    server._handle_message(
        peer=host_peer,
        message=RbResyncRequest(request_id="rq1", from_tick=10, reason="overflow", requested_by_slot=0),
        now_ms=6005,
    )
    sent = _packet_calls(send_packet)
    assert any(
        addr == host_peer.addr and isinstance(packet.message, RelayError) and packet.message.reason == "invalid_resync_sender"
        for addr, packet in sent
    )

    send_packet.reset_mock()
    server._handle_message(
        peer=join_peer,
        message=RbResyncBegin(
            request_id="rq2",
            snapshot_tick=12,
            codec="msgpack_state_v1",
            total_chunks=1,
            compressed_size=3,
            uncompressed_size=3,
        ),
        now_ms=6006,
    )
    sent = _packet_calls(send_packet)
    assert any(
        addr == join_peer.addr and isinstance(packet.message, RelayError) and packet.message.reason == "invalid_resync_sender"
        for addr, packet in sent
    )


def test_host_resync_stream_is_forwarded(mocker) -> None:
    server = RelayServer(RelayServerConfig(bind_host="127.0.0.1", bind_port=0))
    send_packet = _patch_send_capture(mocker, server)
    host_peer, join_peer, _room_code = _start_two_peer_room(server, now_ms=7000)

    send_packet.reset_mock()
    server._handle_message(
        peer=join_peer,
        message=RbResyncRequest(request_id="rq3", from_tick=20, reason="overflow", requested_by_slot=1),
        now_ms=7001,
    )
    sent = _packet_calls(send_packet)
    assert any(
        addr == host_peer.addr and isinstance(packet.message, RbResyncRequest) and packet.message.request_id == "rq3"
        for addr, packet in sent
    )

    send_packet.reset_mock()
    server._handle_message(
        peer=host_peer,
        message=RbResyncChunk(request_id="rq3", chunk_index=0, payload=b"abc"),
        now_ms=7002,
    )
    server._handle_message(
        peer=host_peer,
        message=RbResyncCommit(request_id="rq3", snapshot_tick=20),
        now_ms=7003,
    )

    sent = _packet_calls(send_packet)
    assert any(
        addr == join_peer.addr and isinstance(packet.message, RbResyncChunk) and packet.message.request_id == "rq3"
        for addr, packet in sent
    )
    assert any(
        addr == join_peer.addr and isinstance(packet.message, RbResyncCommit) and packet.message.request_id == "rq3"
        for addr, packet in sent
    )
