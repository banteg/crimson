from __future__ import annotations

from typing import Any

from crimson.net.relay_protocol import (
    PROTOCOL_VERSION,
    ClientHello,
    ClientWelcome,
    RoomCreate,
    RoomJoin,
    RoomReady,
    RoomStart,
    RoomState,
)
from crimson.net.relay_service import RelayServer, RelayServerConfig


def _patch_send_capture(monkeypatch, server: RelayServer) -> list[tuple[tuple[str, int], Any]]:
    sent: list[tuple[tuple[str, int], Any]] = []
    monkeypatch.setattr(
        type(server.transport),
        "send_packet",
        lambda _self, addr, packet: sent.append((addr, packet)),
    )
    return sent


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


def test_room_create_join_ready_start_flow(monkeypatch) -> None:
    server = RelayServer(RelayServerConfig(bind_host="127.0.0.1", bind_port=0))
    sent = _patch_send_capture(monkeypatch, server)

    host_addr = ("127.0.0.1", 40101)
    join_addr = ("127.0.0.1", 40102)

    host_peer = _hello_peer(server, addr=host_addr, build_id="0.1.0", now_ms=1000)
    assert any(addr == host_addr and isinstance(packet.message, ClientWelcome) for addr, packet in sent)
    sent.clear()

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
    assert room_code in server._rooms
    assert any(isinstance(packet.message, RoomState) for _addr, packet in sent)
    sent.clear()

    join_peer = _hello_peer(server, addr=join_addr, build_id="0.1.0", now_ms=1002)
    server._handle_message(
        peer=join_peer,
        message=RoomJoin(room_code=room_code, reconnect_token=""),
        now_ms=1003,
    )
    assert int(join_peer.slot_index) == 1
    assert str(join_peer.room_code) == room_code
    assert any(isinstance(packet.message, RoomState) for _addr, packet in sent)
    sent.clear()

    server._handle_message(
        peer=join_peer,
        message=RoomReady(slot_index=1, ready=True),
        now_ms=1004,
    )
    room = server._rooms[room_code]
    assert room.started is True
    room_start_addrs = {addr for addr, packet in sent if isinstance(packet.message, RoomStart)}
    assert room_start_addrs == {host_addr, join_addr}


def test_reconnect_token_reclaims_slot_and_receives_room_start(monkeypatch) -> None:
    server = RelayServer(RelayServerConfig(bind_host="127.0.0.1", bind_port=0))
    sent = _patch_send_capture(monkeypatch, server)
    host_peer, join_peer, room_code = _start_two_peer_room(server, now_ms=2000)
    room = server._rooms[room_code]
    reconnect_token = str(room.slots[1].reconnect_token)
    assert reconnect_token

    server._disconnect_peer(peer=join_peer, reason="timeout", now_ms=2200)
    assert room.slots[1].connected is False
    assert server._room_by_reconnect[reconnect_token] == (room_code, 1)

    sent.clear()
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
    assert any(addr == new_addr and isinstance(packet.message, RoomStart) for addr, packet in sent)
    assert str(room.slots[0].peer_id) == str(host_peer.peer_id)
