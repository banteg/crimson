from __future__ import annotations

import pyray as rl

from ...debug import debug_enabled
from .base import PanelMenuView

from ..types import GameState


class LanLobbyPanelView(PanelMenuView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="LAN Lobby",
            body="Waiting for peers to connect and ready up.",
            panel_height=360.0,
            back_action="open_play_game",
        )
        self._error: str = ""

    def open(self) -> None:
        super().open()
        self._error = ""

    def _begin_close_transition(self, action: str) -> None:
        if action == "open_play_game":
            runtime = getattr(self.state, "lan_runtime", None)
            if runtime is not None:
                runtime.close()
            self.state.lan_runtime = None
            self.state.lan_in_lobby = False
            self.state.lan_waiting_for_players = False
            self.state.lan_expected_players = 1
            self.state.lan_connected_players = 1
        super()._begin_close_transition(action)

    def update(self, dt: float) -> None:
        super().update(dt)
        if self._closing:
            return

        if self._timeline_ms < self._timeline_max_ms:
            return

        pending = getattr(self.state, "pending_lan_session", None)
        runtime = getattr(self.state, "lan_runtime", None)
        if pending is None or runtime is None:
            self._error = "LAN runtime is not running."
            return

        error = str(getattr(runtime, "error", "") or "")
        if error:
            self._error = error
            return

        match_start_fn = getattr(runtime, "match_start", None)
        if not callable(match_start_fn):
            return
        event = match_start_fn()
        if event is None:
            return

        mode_id = int(getattr(event, "mode_id", 0) or 0)
        player_count = int(getattr(event, "player_count", 1) or 1)
        quest_level = str(getattr(event, "quest_level", "") or "")

        self.state.lan_in_lobby = True
        self.state.lan_waiting_for_players = False
        self.state.lan_expected_players = max(1, min(4, int(player_count)))
        self.state.lan_connected_players = int(self.state.lan_expected_players)
        self.state.config.player_count = int(self.state.lan_expected_players)
        self.state.config.game_mode = int(mode_id)
        if int(mode_id) == 3:
            self.state.pending_quest_level = quest_level

        action = {1: "start_survival", 2: "start_rush", 3: "start_quest"}.get(int(mode_id))
        if action is None:
            self._error = f"Unsupported LAN mode id: {mode_id}"
            return
        self._begin_close_transition(action)

    def _draw_contents(self) -> None:
        super()._draw_contents()

        x = 32.0
        y = 208.0
        line_h = 20.0

        pending = getattr(self.state, "pending_lan_session", None)
        role = str(getattr(pending, "role", "") or "")
        cfg = getattr(pending, "config", None)
        host_ip = str(getattr(cfg, "host_ip", "") or "")
        bind_host = str(getattr(cfg, "bind_host", "") or "")
        port = int(getattr(cfg, "port", 0) or 0)

        runtime = getattr(self.state, "lan_runtime", None)
        lobby_state_fn = getattr(runtime, "lobby_state", None) if runtime is not None else None
        lobby_state = lobby_state_fn() if callable(lobby_state_fn) else None

        session_id = str(getattr(lobby_state, "session_id", "") or "")
        expected = int(getattr(lobby_state, "player_count", self.state.lan_expected_players) or 1)
        slots = getattr(lobby_state, "slots", None) if lobby_state is not None else None
        connected = 0
        if isinstance(slots, list):
            connected = sum(1 for slot in slots if bool(getattr(slot, "connected", False)))
        else:
            connected = int(getattr(self.state, "lan_connected_players", 0) or 0)
        connected = max(0, min(4, int(connected)))
        expected = max(1, min(4, int(expected)))

        dots = "." * int((self._cursor_pulse_time * 2.5) % 4)
        status = f"Connected peers: {connected}/{expected}{dots}"
        role_label = "Host" if role == "host" else "Client"
        where = f"Bind: {bind_host}:{port}" if role == "host" else f"Host: {host_ip}:{port}"

        rl.draw_text(status, int(x), int(y), 18, rl.Color(225, 235, 247, 255))
        y += line_h
        rl.draw_text(f"Role: {role_label}", int(x), int(y), 18, rl.Color(185, 205, 230, 255))
        y += line_h
        rl.draw_text(where, int(x), int(y), 18, rl.Color(185, 205, 230, 255))
        y += line_h

        if session_id:
            rl.draw_text(f"Session: {session_id}", int(x), int(y), 18, rl.Color(155, 175, 200, 255))
            y += line_h

        if isinstance(slots, list) and slots:
            y += 8.0
            rl.draw_text("Slots:", int(x), int(y), 18, rl.Color(200, 200, 210, 255))
            y += line_h
            for slot in slots[:4]:
                idx = int(getattr(slot, "slot_index", -1) or -1)
                is_host = bool(getattr(slot, "is_host", False))
                ready = bool(getattr(slot, "ready", False))
                conn = bool(getattr(slot, "connected", False))
                name = str(getattr(slot, "peer_name", "") or "")
                label = "host" if is_host else (name or "peer")
                state = "READY" if ready else ("CONNECTED" if conn else "EMPTY")
                color = rl.Color(160, 220, 160, 255) if ready else rl.Color(210, 210, 210, 255)
                rl.draw_text(f"[{idx}] {label:8s} {state}", int(x), int(y), 16, color)
                y += 18.0

        if self._error:
            y += 10.0
            rl.draw_text(self._error, int(x), int(y), 16, rl.Color(240, 90, 90, 255))
            y += 18.0

        if debug_enabled():
            y += 12.0
            base_dir = getattr(self.state, "base_dir", None)
            rl.draw_text("Debug:", int(x), int(y), 18, rl.Color(232, 197, 117, 255))
            y += line_h
            if base_dir is not None:
                rl.draw_text(
                    f"logs: {str(base_dir)}/logs/lan/",
                    int(x),
                    int(y),
                    16,
                    rl.Color(232, 197, 117, 255),
                )
