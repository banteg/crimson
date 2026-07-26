from __future__ import annotations

from unittest.mock import MagicMock

from crimson.game_modes import GameMode
from crimson.net.relay_protocol import (
    NetMessage,
    RbResyncBegin,
    RbResyncChunk,
    RbResyncCommit,
    RbResyncRequest,
    RoomStart,
)
from crimson.net.rollback_resync_v5 import (
    RushRuntimeSnapshotV2,
    RushStateSnapshotV2,
    SurvivalRuntimeSnapshotV2,
    SurvivalStateSnapshotV2,
    encode_mode_snapshot,
)
from crimson.net.rollback_runtime import (
    HostRollbackRuntimeConfig,
    JoinRollbackRuntimeConfig,
    RollbackRuntime,
)


def _sent_messages(send_packet: MagicMock) -> list[NetMessage]:
    return [call.args[-1].message for call in send_packet.call_args_list]


def _started_runtime(mocker, *, role: str, slot_index: int) -> tuple[RollbackRuntime, MagicMock]:
    cfg_type = HostRollbackRuntimeConfig if role == "host" else JoinRollbackRuntimeConfig
    runtime = RollbackRuntime(
        cfg_type(
            mode_id=GameMode.SURVIVAL,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="ab12",
            input_delay_ticks=0,
        ),
    )
    send_packet = mocker.patch.object(type(runtime.transport), "send_packet")
    runtime._server_addr = ("127.0.0.1", 31993)
    runtime._accepted = True
    runtime._joined_room = True
    runtime._sent_ready = True
    runtime._handle_message(
        message=RoomStart(
            room_code="ab12",
            session_id="s1",
            mode_id=GameMode.SURVIVAL,
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
    return runtime, send_packet


def test_resync_request_to_stream_to_apply_flow(mocker) -> None:
    join, _join_sent = _started_runtime(mocker, role="join", slot_index=1)
    host, host_send_packet = _started_runtime(mocker, role="host", slot_index=0)

    payload = encode_mode_snapshot(
        snapshot=SurvivalStateSnapshotV2(
            tick_index=8,
            runtime_state=SurvivalRuntimeSnapshotV2(
                elapsed_ms=8.0,
                stage=1,
                spawn_cooldown_ms=0.0,
                perk_pending_count=0,
            ),
        ),
    )
    host.store_local_snapshot(8, payload)

    host._handle_message(
        message=RbResyncRequest(request_id="rq1", from_tick=4, reason="overflow", requested_by_slot=1),
        now_ms=1200,
    )

    stream_messages = [message for message in _sent_messages(host_send_packet) if type(message).__name__.startswith("RbResync")]
    for message in stream_messages:
        join._handle_message(message=message, now_ms=1201)

    pending = join.pop_resync_snapshot()
    assert pending is not None
    assert pending[0] == 8
    assert pending[1] == payload

    join.mark_resync_applied(8)
    join.queue_local_input([0.0, 0.0, 0.0, 0.0, 1], now_ms=1202)
    assert join.pop_tick_frame() is not None


def test_resync_checksum_mismatch_sets_error(mocker) -> None:
    join, _join_sent = _started_runtime(mocker, role="join", slot_index=1)
    host, host_send_packet = _started_runtime(mocker, role="host", slot_index=0)

    payload = encode_mode_snapshot(
        snapshot=RushStateSnapshotV2(
            tick_index=16,
            runtime_state=RushRuntimeSnapshotV2(
                elapsed_ms=16.0,
                spawn_cooldown_ms=0.0,
                kill_count=0,
            ),
        ),
    )
    host.store_local_snapshot(16, payload)
    host._handle_message(
        message=RbResyncRequest(request_id="rq2", from_tick=10, reason="overflow", requested_by_slot=1),
        now_ms=1300,
    )

    begin: RbResyncBegin | None = None
    chunks: list[RbResyncChunk] = []
    commit: RbResyncCommit | None = None
    for message in _sent_messages(host_send_packet):
        if isinstance(message, RbResyncBegin):
            begin = message
        elif isinstance(message, RbResyncChunk):
            chunks.append(message)
        elif isinstance(message, RbResyncCommit):
            commit = message

    assert begin is not None
    assert commit is not None

    join._handle_message(message=begin, now_ms=1301)
    for chunk in chunks:
        join._handle_message(message=chunk, now_ms=1302)

    broken_commit = RbResyncCommit(
        request_id=commit.request_id,
        snapshot_tick=commit.snapshot_tick + 1,
    )
    join._handle_message(message=broken_commit, now_ms=1303)

    assert join.error == "resync_commit_error"
