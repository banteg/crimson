from __future__ import annotations

import random
import time
from pathlib import Path
from types import SimpleNamespace

from crimson.frontend.panels.lan_lobby import LanLobbyPanelView
from crimson.frontend.panels.lan_session import LanSessionPanelView
from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState, LanSessionConfig, PendingLanSession
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.geom import Vec2


def _build_state(tmp_path: Path) -> GameState:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"
    cfg = ensure_crimson_cfg(tmp_path)
    return GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=random.Random(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=False,
        preserve_bugs=False,
        logos=None,
        texture_cache=None,
        audio=None,
        resource_paq=assets_dir / "crimson.paq",
        session_start=time.monotonic(),
    )


def test_network_session_panel_requires_room_code_for_join(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    panel = LanSessionPanelView(state)
    panel._role = "join"
    panel._host_ip = "127.0.0.1"
    panel._room_code = ""

    panel._start_session()

    assert "Room code is required" in panel._error
    assert state.pending_net_session is None
    assert state.pending_lan_session is None


def test_network_session_panel_writes_pending_net_and_legacy_alias(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    panel = LanSessionPanelView(state)
    panel._role = "host"
    panel._mode_idx = 1  # rush
    panel._player_count = 3
    panel._bind_host = "203.0.113.20"
    panel._port_text = "32031"
    panel._room_code = "rB42"
    panel._netcode_mode = "lockstep_legacy"

    panel._start_session()

    pending = state.pending_net_session
    assert pending is not None
    assert state.pending_lan_session is pending
    assert pending.role == "host"
    assert pending.config.mode == "rush"
    assert pending.config.player_count == 3
    assert pending.config.relay_host == "203.0.113.20"
    assert pending.config.relay_port == 32031
    assert pending.config.room_code == "RB42"
    assert pending.config.netcode_mode == "lockstep_legacy"


def test_loop_view_uses_pending_net_session_when_lan_alias_is_unset(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    state.pending_net_session = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode="rush",
            player_count=2,
            quest_level="",
            bind_host="0.0.0.0",
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="",
            host_ip="127.0.0.1",
            port=31993,
            netcode_mode="rollback",
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=False,
    )
    state.pending_lan_session = None
    loop = GameLoopView(state)

    action = loop._resolve_lan_action("start_rush_lan")

    assert action == "open_lan_lobby"
    assert state.net_runtime is not None
    assert state.lan_runtime is state.net_runtime
    assert state.net_in_lobby is True
    assert state.lan_in_lobby is True


def test_network_lobby_panel_shows_room_code_not_session_id(monkeypatch, tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    pending = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode="survival",
            player_count=2,
            quest_level="",
            bind_host="0.0.0.0",
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="ZZ99",
            host_ip="127.0.0.1",
            port=31993,
            netcode_mode="rollback",
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
    )
    state.pending_net_session = pending
    state.pending_lan_session = pending
    state.net_runtime = SimpleNamespace(
        lobby_state=lambda: SimpleNamespace(room_code="AB12", session_id="session123", player_count=2, slots=[]),
    )
    state.lan_runtime = state.net_runtime

    panel = LanLobbyPanelView(state)
    captured: list[str] = []
    monkeypatch.setattr(
        "crimson.frontend.panels.lan_lobby.draw_small_text",
        lambda _font, text, _pos, _scale, _color: captured.append(str(text)),
    )
    monkeypatch.setattr(
        "crimson.frontend.panels.lan_lobby.measure_small_text_width",
        lambda _font, text, _scale: float(len(str(text)) * 8),
    )
    monkeypatch.setattr(panel, "_ensure_small_font", lambda: SimpleNamespace(cell_size=8))
    monkeypatch.setattr(
        panel,
        "_layout",
        lambda: SimpleNamespace(
            scale=1.0,
            panel_top_left=Vec2(0.0, 0.0),
            base_pos=Vec2(0.0, 0.0),
            back_pos=Vec2(0.0, 0.0),
            back_w=64.0,
        ),
    )

    panel._draw_contents()

    code_label_index = captured.index("Code:")
    assert captured[code_label_index + 1] == "AB12"
    assert "Session:" in captured
