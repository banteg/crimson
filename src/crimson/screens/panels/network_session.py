from __future__ import annotations

import msgspec

from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game.types import (
    BackToPrevious,
    FrontRouteId,
    GameState,
    LockstepEndpoint,
    NetcodeMode,
    NetworkSessionConfig,
    NetworkSessionMode,
    OpenLanLobby,
    PendingNetworkSession,
    RollbackEndpoint,
    ScreenAction,
)
from ...net.relay_protocol import ROOM_CODE_LENGTH
from ...net.room_code import parse_optional_room_code
from ...quests.level import QuestLevel
from ...ui.perk_menu import UiButtonState, button_draw
from ...ui.text_input import poll_text_input
from ..assets import require_runtime_resources
from ..chrome.geometry import MENU_PANEL_OFFSET_Y
from .base import _PanelMenuScreenView


class _SessionLayout(msgspec.Struct, frozen=True):
    scale: float
    panel_top_left: Vec2
    base_pos: Vec2
    back_pos: Vec2
    back_w: float


class NetworkSessionPanelView(_PanelMenuScreenView):
    _MODES: tuple[NetworkSessionMode, ...] = ("survival", "rush", "quests")

    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="Network Session",
            panel_offset=Vec2(-63.0, MENU_PANEL_OFFSET_Y),
            panel_height=278.0,
            back_action=BackToPrevious(),
        )
        self._uses_button_back_control = True
        self._back_button = UiButtonState("Back", force_wide=False)

        self._role: str = "host"
        self._mode_idx: int = 0
        self._player_count: int = 2
        self._quest_level: str = "1.1"
        self._bind_host: str = "127.0.0.1"
        self._host: str = "127.0.0.1"
        self._room_code: str = ""
        self._netcode_mode: NetcodeMode = "rollback"
        self._port_text: str = "31993"
        self._active_field: str = ""
        self._error: str = ""

    def _parsed_quest_level(self) -> QuestLevel | None:
        value = self._quest_level.strip()
        if not value:
            return None
        return QuestLevel.parse(value)

    def open(self) -> None:
        super().open()

        self._back_button = UiButtonState("Back", force_wide=False)

        pending = self.state.pending_network_session
        if pending is not None:
            self._role = str(pending.role)
            cfg = pending.config
            try:
                self._mode_idx = self._MODES.index(str(cfg.mode))
            except ValueError:
                self._mode_idx = 0
            self._player_count = max(1, min(4, int(cfg.player_count)))
            self._quest_level = str(cfg.quest_level or "1.1")
            netcode_raw = str(cfg.netcode_mode).strip().lower()
            self._netcode_mode = "lockstep" if netcode_raw == "lockstep" else "rollback"
            endpoint = cfg.endpoint
            if isinstance(endpoint, LockstepEndpoint):
                self._bind_host = str(endpoint.bind_host or "0.0.0.0")
                self._host = str(endpoint.host or "127.0.0.1")
                self._room_code = ""
                self._port_text = str(max(1, int(endpoint.port)))
            else:
                self._bind_host = str(endpoint.relay_host or "127.0.0.1")
                self._host = str(endpoint.relay_host or "127.0.0.1")
                self._room_code = "".join(ch for ch in str(endpoint.room_code or "").lower() if ch.isalnum())[
                    : int(ROOM_CODE_LENGTH)
                ]
                self._port_text = str(max(1, int(endpoint.relay_port)))

        self._active_field = ""
        self._error = ""

    def update(self, dt: float) -> None:
        super().update(dt)
        chrome = self._chrome_state
        if chrome.closing or chrome.timeline_ms < chrome.timeline_max_ms:
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
            self._active_field = "host"
        if rl.is_key_pressed(rl.KeyboardKey.KEY_B):
            self._active_field = "bind_host"
        if rl.is_key_pressed(rl.KeyboardKey.KEY_C) and self._netcode_mode == "rollback":
            self._active_field = "room_code"
        if rl.is_key_pressed(rl.KeyboardKey.KEY_N):
            self._netcode_mode = "lockstep" if self._netcode_mode == "rollback" else "rollback"
            if self._netcode_mode == "lockstep":
                self._room_code = ""
                if not self._host.strip():
                    self._host = "127.0.0.1"
            self._active_field = ""
        if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._active_field = "port"

        typed = poll_text_input(64, allow_space=False)
        if typed:
            if self._active_field == "quest_level":
                self._quest_level = (self._quest_level + typed)[:8]
            elif self._active_field == "bind_host":
                self._bind_host = (self._bind_host + typed)[:64]
            elif self._active_field == "host":
                self._host = (self._host + typed)[:64]
            elif self._active_field == "room_code":
                self._room_code = "".join(ch for ch in (self._room_code + typed).lower() if ch.isalnum())[
                    : int(ROOM_CODE_LENGTH)
                ]
            elif self._active_field == "port":
                self._port_text = "".join(ch for ch in (self._port_text + typed) if ch.isdigit())[:5]

        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
            if self._active_field == "quest_level" and self._quest_level:
                self._quest_level = self._quest_level[:-1]
            elif self._active_field == "bind_host" and self._bind_host:
                self._bind_host = self._bind_host[:-1]
            elif self._active_field == "host" and self._host:
                self._host = self._host[:-1]
            elif self._active_field == "room_code" and self._room_code:
                self._room_code = self._room_code[:-1]
            elif self._active_field == "port" and self._port_text:
                self._port_text = self._port_text[:-1]

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self._start_session()

    def _layout(self) -> _SessionLayout:
        frame = self._panel_frame()
        panel_scale = frame.scale
        panel_top_left = frame.panel_top_left
        base_pos = panel_top_left + Vec2(212.0 * panel_scale, 40.0 * panel_scale)
        back_pos, back_w = self._button_back_layout()

        return _SessionLayout(
            scale=panel_scale,
            panel_top_left=panel_top_left,
            base_pos=base_pos,
            back_pos=back_pos,
            back_w=float(back_w),
        )

    def _current_mode(self) -> NetworkSessionMode:
        idx = max(0, min(int(self._mode_idx), len(self._MODES) - 1))
        return self._MODES[idx]

    def _parse_port(self) -> int:
        try:
            port = int(self._port_text)
        except ValueError:
            port = 31993
        return max(1, min(65535, int(port)))

    def _mode_start_action(self, mode: NetworkSessionMode) -> ScreenAction:
        if mode == "rush":
            return OpenLanLobby(FrontRouteId.START_RUSH)
        if mode == "quests":
            return OpenLanLobby(FrontRouteId.START_QUEST)
        return OpenLanLobby(FrontRouteId.START_SURVIVAL)

    def _start_session(self) -> None:
        self._error = ""
        mode = self._current_mode()
        port = self._parse_port()
        try:
            quest_level = self._parsed_quest_level()
        except ValueError:
            self._error = "Quest level must use the format major.minor."
            return

        if mode == "quests" and quest_level is None:
            self._error = "Quest level is required for quest network sessions."
            return

        if self._netcode_mode == "lockstep":
            if not self._host.strip():
                self._error = "Host is required for lockstep sessions."
                return
            endpoint = LockstepEndpoint(
                bind_host=str(self._bind_host.strip() or "0.0.0.0"),
                host=str(self._host.strip()),
                port=int(port),
            )
            config = NetworkSessionConfig(
                mode=mode,
                endpoint=endpoint,
                netcode_mode="lockstep",
                player_count=max(1, min(4, int(self._player_count))),
                quest_level=quest_level,
                rollback_max_ticks=8,
                reconnect_timeout_ms=15_000,
                input_delay_ticks=1,
                preserve_bugs=False,
            )
        else:
            if not self._host.strip():
                self._error = "Relay host is required for rollback sessions."
                return
            if self._role == "join" and not self._room_code.strip():
                self._error = "Room code is required to join rollback sessions."
                return
            try:
                room_code = parse_optional_room_code(self._room_code)
            except msgspec.ValidationError:
                self._error = f"Room code must be {int(ROOM_CODE_LENGTH)} uppercase letters or digits."
                return
            endpoint = RollbackEndpoint(
                relay_host=str(self._host.strip()),
                relay_port=int(port),
                room_code=room_code,
            )
            config = NetworkSessionConfig(
                mode=mode,
                endpoint=endpoint,
                netcode_mode="rollback",
                player_count=max(1, min(4, int(self._player_count))),
                quest_level=quest_level,
                rollback_max_ticks=8,
                reconnect_timeout_ms=15_000,
                input_delay_ticks=1,
                preserve_bugs=False,
            )

        pending = PendingNetworkSession(
            role=("host" if self._role == "host" else "join"),
            config=config,
            auto_start=False,
        )
        self.state.pending_network_session = pending
        self._begin_close_transition(self._mode_start_action(mode))

    def _draw_contents(self) -> None:
        layout = self._layout()
        resources = require_runtime_resources(self.state)
        font = resources.small_font
        scale = float(layout.scale)
        base_pos = layout.base_pos
        text_scale = 1.0 * scale

        title_scale = 1.2 * scale
        title_color = rl.Color(255, 255, 255, 255)
        body_color = rl.Color(190, 210, 230, 220)
        label_color = rl.Color(190, 190, 200, 230)
        value_color = rl.Color(225, 235, 247, 255)
        active_color = rl.Color(232, 197, 117, 255)

        draw_small_text(font, "Network Session", base_pos, title_color)
        y = base_pos.y + float(font.cell_size) * title_scale + 6.0 * scale
        draw_small_text(font, "TAB role | M mode | [/] players | N netcode | H/B/P/C/L edit | ENTER continue", Vec2(base_pos.x, y), body_color)
        y += float(font.cell_size) * 0.9 * scale + 10.0 * scale

        mode = self._current_mode()
        role_label = "Host" if self._role == "host" else "Join"

        label_w = max(
            measure_small_text_width(font, "Role:"),
            measure_small_text_width(font, "Mode:"),
            measure_small_text_width(font, "Players:"),
            measure_small_text_width(font, "Netcode:"),
            measure_small_text_width(font, "Bind:"),
            measure_small_text_width(font, "Host:"),
            measure_small_text_width(font, "Relay:"),
            measure_small_text_width(font, "Code:"),
            measure_small_text_width(font, "Port:"),
            measure_small_text_width(font, "Quest:"),
        )
        value_x = base_pos.x + label_w + 10.0 * scale
        line_h = float(font.cell_size) * text_scale + 3.0 * scale

        draw_small_text(font, "Role:", Vec2(base_pos.x, y), label_color)
        draw_small_text(font, role_label, Vec2(value_x, y), value_color)
        y += line_h

        draw_small_text(font, "Mode:", Vec2(base_pos.x, y), label_color)
        draw_small_text(font, str(mode), Vec2(value_x, y), value_color)
        y += line_h

        draw_small_text(font, "Players:", Vec2(base_pos.x, y), label_color)
        draw_small_text(font, str(self._player_count), Vec2(value_x, y), value_color)
        y += line_h

        draw_small_text(font, "Netcode:", Vec2(base_pos.x, y), label_color)
        draw_small_text(font, str(self._netcode_mode), Vec2(value_x, y), value_color)
        y += line_h

        if self._netcode_mode == "lockstep":
            draw_small_text(font, "Bind:", Vec2(base_pos.x, y), label_color)
            bind_tint = active_color if self._active_field == "bind_host" else value_color
            draw_small_text(font, self._bind_host or "-", Vec2(value_x, y), bind_tint)
            y += line_h

            draw_small_text(font, "Host:", Vec2(base_pos.x, y), label_color)
            host_tint = active_color if self._active_field == "host" else value_color
            draw_small_text(font, self._host or "-", Vec2(value_x, y), host_tint)
            y += line_h
        else:
            draw_small_text(font, "Relay:", Vec2(base_pos.x, y), label_color)
            relay_tint = active_color if self._active_field == "host" else value_color
            draw_small_text(font, self._host or "-", Vec2(value_x, y), relay_tint)
            y += line_h

            draw_small_text(font, "Code:", Vec2(base_pos.x, y), label_color)
            code_tint = active_color if self._active_field == "room_code" else value_color
            draw_small_text(font, self._room_code or "-", Vec2(value_x, y), code_tint)
            y += line_h

        draw_small_text(font, "Port:", Vec2(base_pos.x, y), label_color)
        port_tint = active_color if self._active_field == "port" else value_color
        draw_small_text(font, self._port_text or "-", Vec2(value_x, y), port_tint)
        y += line_h

        if mode == "quests":
            draw_small_text(font, "Quest:", Vec2(base_pos.x, y), label_color)
            quest_tint = active_color if self._active_field == "quest_level" else value_color
            draw_small_text(font, self._quest_level or "-", Vec2(value_x, y), quest_tint)
            y += line_h

        if self._error:
            y += float(font.cell_size) * 0.9 * scale + 6.0 * scale
            draw_small_text(font, self._error, Vec2(base_pos.x, y), rl.Color(240, 90, 90, 255))

        assert self._back_button is not None
        button_draw(
            resources,
            self._back_button,
            pos=layout.back_pos,
            width=float(layout.back_w),
            scale=scale,
        )
