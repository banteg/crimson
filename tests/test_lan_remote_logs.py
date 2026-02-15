from __future__ import annotations

from pathlib import Path

from crimson.net.debug_log import close_lan_debug_log, init_lan_debug_log
from crimson.net.lobby import HostLobby
from crimson.net.protocol import DebugLogBatch, Hello, INPUT_DELAY_TICKS, PROTOCOL_VERSION, TICK_RATE
from crimson.net.runtime import LanRuntime, LanRuntimeConfig


def test_host_writes_remote_client_log_batches(tmp_path: Path) -> None:
    close_lan_debug_log()
    host_log_path = init_lan_debug_log(
        base_dir=tmp_path,
        role="host",
        mode="survival",
        build_id="0.1.0",
        host="127.0.0.1",
        port=31993,
        player_count=2,
        auto_start=True,
        debug_enabled=True,
    )

    runtime = LanRuntime(
        LanRuntimeConfig(
            role="host",
            mode_id=1,
            player_count=2,
            bind_host="127.0.0.1",
            host_ip="",
            port=0,
        )
    )
    lobby = HostLobby(
        mode_id=1,
        player_count=2,
        build_id="0.1.0",
        tick_rate=TICK_RATE,
        input_delay_ticks=INPUT_DELAY_TICKS,
    )
    addr = ("10.0.0.2", 32001)
    welcome = lobby.process_hello(
        addr,
        Hello(
            protocol_version=int(PROTOCOL_VERSION),
            build_id="0.1.0",
            mode_id=1,
            player_count=2,
            tick_rate=TICK_RATE,
            input_delay_ticks=INPUT_DELAY_TICKS,
            quest_level="",
            preserve_bugs=False,
            host=False,
        ),
    )
    assert welcome.accepted is True

    runtime.host_lobby = lobby
    runtime._handle_host_message(
        addr,
        DebugLogBatch(slot_index=int(welcome.slot_index), lines=["2000-01-01T00:00:00.000Z event=test foo=bar\n"]),
        now_ms=0,
    )

    remote_logs = list(host_log_path.parent.glob(f"lan-client-slot{int(welcome.slot_index)}-*.log"))
    assert len(remote_logs) == 1
    text = remote_logs[0].read_text(encoding="utf-8")
    assert "event=remote_log_init" in text
    assert "event=test" in text

    close_lan_debug_log()
