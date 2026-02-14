from __future__ import annotations

import pyray as rl

from ...game.types import LanSessionConfig, LanSessionMode, PendingLanSession
from ...ui.text_input import poll_text_input
from .base import PanelMenuView

from ..types import GameState


class LanSessionPanelView(PanelMenuView):
    _MODES: tuple[LanSessionMode, ...] = ("survival", "rush", "quests")

    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="LAN Session",
            body="Host or join a LAN lockstep session.",
            panel_height=304.0,
            back_action="open_play_game",
        )
        self._role: str = "host"
        self._mode_idx: int = 0
        self._player_count: int = 2
        self._quest_level: str = "1.1"
        self._bind_host: str = "0.0.0.0"
        self._host_ip: str = "127.0.0.1"
        self._port_text: str = "31993"
        self._active_field: str = ""
        self._error: str = ""

    def open(self) -> None:
        super().open()
        pending = self.state.pending_lan_session
        if pending is not None:
            self._role = str(pending.role)
            cfg = pending.config
            try:
                self._mode_idx = self._MODES.index(str(cfg.mode))
            except ValueError:
                self._mode_idx = 0
            self._player_count = max(1, min(4, int(cfg.player_count)))
            self._quest_level = str(cfg.quest_level or "1.1")
            self._bind_host = str(cfg.bind_host or "0.0.0.0")
            self._host_ip = str(cfg.host_ip or "127.0.0.1")
            self._port_text = str(int(cfg.port)) if int(cfg.port) > 0 else "31993"
        self._active_field = ""
        self._error = ""

    def update(self, dt: float) -> None:
        super().update(dt)
        if self._closing:
            return

        if self._timeline_ms < self._timeline_max_ms:
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._role = "join" if self._role == "host" else "host"
            self._active_field = ""

        if self._role == "host":
            if rl.is_key_pressed(rl.KeyboardKey.KEY_M):
                self._mode_idx = (int(self._mode_idx) + 1) % len(self._MODES)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
                self._player_count = max(1, int(self._player_count) - 1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
                self._player_count = min(4, int(self._player_count) + 1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_L):
                self._active_field = "quest_level"

        if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
            self._active_field = "host_ip" if self._role == "join" else "bind_host"
        if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._active_field = "port"

        typed = poll_text_input(64, allow_space=False)
        if typed:
            if self._active_field == "quest_level":
                self._quest_level = (self._quest_level + typed)[:8]
            elif self._active_field == "bind_host":
                self._bind_host = (self._bind_host + typed)[:64]
            elif self._active_field == "host_ip":
                self._host_ip = (self._host_ip + typed)[:64]
            elif self._active_field == "port":
                self._port_text = "".join(ch for ch in (self._port_text + typed) if ch.isdigit())[:5]

        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
            if self._active_field == "quest_level" and self._quest_level:
                self._quest_level = self._quest_level[:-1]
            elif self._active_field == "bind_host" and self._bind_host:
                self._bind_host = self._bind_host[:-1]
            elif self._active_field == "host_ip" and self._host_ip:
                self._host_ip = self._host_ip[:-1]
            elif self._active_field == "port" and self._port_text:
                self._port_text = self._port_text[:-1]

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self._start_session()

    def _current_mode(self) -> LanSessionMode:
        idx = max(0, min(int(self._mode_idx), len(self._MODES) - 1))
        return self._MODES[idx]

    def _parse_port(self) -> int:
        try:
            port = int(self._port_text)
        except ValueError:
            port = 31993
        return max(1, min(65535, int(port)))

    def _mode_start_action(self, mode: LanSessionMode) -> str:
        if mode == "rush":
            return "start_rush_lan"
        if mode == "quests":
            return "start_quest_lan"
        return "start_survival_lan"

    def _start_session(self) -> None:
        self._error = ""
        mode = self._current_mode()
        port = self._parse_port()

        if self._role == "host":
            if mode == "quests" and not self._quest_level.strip():
                self._error = "Quest level is required for quest LAN sessions."
                return
            pending = PendingLanSession(
                role="host",
                config=LanSessionConfig(
                    mode=mode,
                    player_count=max(1, min(4, int(self._player_count))),
                    quest_level=str(self._quest_level.strip()),
                    bind_host=str(self._bind_host.strip() or "0.0.0.0"),
                    host_ip="",
                    port=int(port),
                    # LAN lockstep is rewrite-only; keep rules consistent and do not expose preserve_bugs here.
                    preserve_bugs=False,
                ),
                auto_start=False,
            )
        else:
            if not self._host_ip.strip():
                self._error = "Host IP is required to join a LAN session."
                return
            pending = PendingLanSession(
                role="join",
                config=LanSessionConfig(
                    mode=mode,
                    player_count=max(1, min(4, int(self._player_count))),
                    quest_level=str(self._quest_level.strip()),
                    bind_host="0.0.0.0",
                    host_ip=str(self._host_ip.strip()),
                    port=int(port),
                    # LAN lockstep is rewrite-only; keep rules consistent and do not expose preserve_bugs here.
                    preserve_bugs=False,
                ),
                auto_start=False,
            )

        self.state.pending_lan_session = pending
        self._begin_close_transition(self._mode_start_action(mode))

    def _draw_contents(self) -> None:
        super()._draw_contents()

        x = 32
        y = 200
        line_h = 20
        role_label = "HOST" if self._role == "host" else "JOIN"
        mode = self._current_mode()

        rl.draw_text(f"Role: {role_label} (TAB to toggle)", x, y, 18, rl.Color(225, 225, 225, 255))
        y += line_h
        rl.draw_text(f"Mode: {mode} (M to cycle)", x, y, 18, rl.Color(225, 225, 225, 255))
        y += line_h
        rl.draw_text(f"Players: {self._player_count} ([ / ] to change)", x, y, 18, rl.Color(225, 225, 225, 255))
        y += line_h

        if self._role == "host":
            rl.draw_text(f"Bind: {self._bind_host} (H then type)", x, y, 18, rl.Color(220, 220, 220, 255))
            y += line_h
        else:
            rl.draw_text(f"Host: {self._host_ip} (H then type)", x, y, 18, rl.Color(220, 220, 220, 255))
            y += line_h

        rl.draw_text(f"Port: {self._port_text} (P then type)", x, y, 18, rl.Color(220, 220, 220, 255))
        y += line_h

        if mode == "quests":
            rl.draw_text(
                f"Quest Level: {self._quest_level} (L then type)",
                x,
                y,
                18,
                rl.Color(220, 220, 220, 255),
            )
            y += line_h

        rl.draw_text("Press ENTER to continue to the selected LAN mode.", x, y + 6, 16, rl.Color(160, 160, 170, 255))

        if self._error:
            rl.draw_text(self._error, x, y + 30, 16, rl.Color(240, 90, 90, 255))
