from __future__ import annotations

from typing import Any

from crimson.net.net_runtime import NetRuntime, NetRuntimeConfig
from crimson.net.relay_protocol import RbResyncRequest, RoomStart
from crimson.net.rollback_resync_v5 import encode_mode_snapshot


def _started_runtime(monkeypatch, *, role: str, slot_index: int) -> tuple[NetRuntime, list[tuple[tuple[str, int], Any]]]:
    runtime = NetRuntime(
        NetRuntimeConfig(
            role=role,
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="AB12",
            input_delay_ticks=0,
        ),
    )
    sent: list[tuple[tuple[str, int], Any]] = []
    monkeypatch.setattr(
        type(runtime.transport),
        "send_packet",
        lambda _self, addr, packet: sent.append((addr, packet)),
    )
    runtime._server_addr = ("127.0.0.1", 31993)
    runtime._accepted = True
    runtime._joined_room = True
    runtime._sent_ready = True
    runtime._handle_message(
        message=RoomStart(
            room_code="AB12",
            session_id="s1",
            mode_id=1,
            player_count=2,
            slot_index=slot_index,
            host_slot_index=0,
            input_delay_ticks=0,
            rollback_max_ticks=8,
            netcode_mode="rollback",
            reconnect_token=f"tok-{slot_index}",
        ),
        now_ms=1000,
    )
    return runtime, sent


def test_resync_request_to_stream_to_apply_flow(monkeypatch) -> None:
    join, _join_sent = _started_runtime(monkeypatch, role="join", slot_index=1)
    host, host_sent = _started_runtime(monkeypatch, role="host", slot_index=0)

    payload = encode_mode_snapshot(
        mode="survival",
        tick_index=8,
        session_state={"elapsed_ms": 8.0},
        mode_state={"stage": 1},
    )
    host.store_local_snapshot(8, payload)

    host._handle_message(
        message=RbResyncRequest(request_id="rq1", from_tick=4, reason="overflow", requested_by_slot=1),
        now_ms=1200,
    )

    stream_messages = [packet.message for _addr, packet in host_sent if type(packet.message).__name__.startswith("RbResync")]
    for message in stream_messages:
        join._handle_message(message=message, now_ms=1201)

    pending = join.pop_resync_snapshot()
    assert pending is not None
    assert pending[0] == 8
    assert pending[1] == payload

    join.mark_resync_applied(8)
    join.queue_local_input([0.0, 0.0, [0.0, 0.0], 1], now_ms=1202)
    assert join.pop_tick_frame() is not None


def test_resync_checksum_mismatch_sets_error(monkeypatch) -> None:
    join, _join_sent = _started_runtime(monkeypatch, role="join", slot_index=1)
    host, host_sent = _started_runtime(monkeypatch, role="host", slot_index=0)

    payload = encode_mode_snapshot(
        mode="rush",
        tick_index=16,
        session_state={"elapsed_ms": 16.0},
        mode_state={"spawn_cooldown_ms": 0.0},
    )
    host.store_local_snapshot(16, payload)
    host._handle_message(
        message=RbResyncRequest(request_id="rq2", from_tick=10, reason="overflow", requested_by_slot=1),
        now_ms=1300,
    )

    begin = None
    chunks: list[Any] = []
    commit = None
    for _addr, packet in host_sent:
        message = packet.message
        kind = type(message).__name__
        if kind == "RbResyncBegin":
            begin = message
        elif kind == "RbResyncChunk":
            chunks.append(message)
        elif kind == "RbResyncCommit":
            commit = message

    assert begin is not None
    assert commit is not None

    join._handle_message(message=begin, now_ms=1301)
    for chunk in chunks:
        join._handle_message(message=chunk, now_ms=1302)

    broken_commit = type(commit)(
        request_id=commit.request_id,
        snapshot_tick=commit.snapshot_tick,
        payload_sha256="0" * 64,
    )
    join._handle_message(message=broken_commit, now_ms=1303)

    assert join.error == "resync_commit_error"
