from __future__ import annotations

from pathlib import Path

from crimson.net.debug_log import (
    close_lan_debug_log,
    init_lan_debug_log,
    lan_debug_log,
    lan_debug_log_path,
    set_lan_debug_forwarder,
)


def test_lan_debug_log_writes_events_to_file(tmp_path: Path) -> None:
    close_lan_debug_log()
    log_path = init_lan_debug_log(
        base_dir=tmp_path,
        role="host",
        mode="survival",
        build_id="test-build",
        host="127.0.0.1",
        port=31993,
        player_count=2,
        auto_start=True,
        debug_enabled=True,
    )
    lan_debug_log("heartbeat", connected_players=1, expected_players=2, waiting_for_players=True)

    assert lan_debug_log_path() == log_path
    text = log_path.read_text(encoding="utf-8")
    assert "event=init" in text
    assert "role=host" in text
    assert "event=heartbeat" in text
    assert "connected_players=1" in text

    close_lan_debug_log()
    assert lan_debug_log_path() is None


def test_lan_debug_log_forwarder_receives_lines(tmp_path: Path) -> None:
    close_lan_debug_log()

    init_lan_debug_log(
        base_dir=tmp_path,
        role="join",
        mode="survival",
        build_id="test-build",
        host="127.0.0.1",
        port=31993,
        player_count=2,
        auto_start=True,
        debug_enabled=True,
    )

    forwarded: list[str] = []

    def _forward(line: str) -> None:
        forwarded.append(line)

    set_lan_debug_forwarder(_forward)
    lan_debug_log("heartbeat", connected_players=1, expected_players=2, waiting_for_players=True)

    assert any("event=heartbeat" in line for line in forwarded)

    close_lan_debug_log()
