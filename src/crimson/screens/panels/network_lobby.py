from __future__ import annotations

import msgspec

from grim.audio import play_sfx, update_audio
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...debug import debug_enabled
from ...game.types import GameState, LockstepEndpoint
from ...game_modes import GameMode
from ...net.lockstep_protocol import LobbyState
from ...net.lockstep_runtime import LockstepRuntime
from ...net.relay_protocol import RoomState
from ...net.rollback_runtime import RollbackRuntime
from ...ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from ..assets import require_runtime_resources
from ..menu import MENU_PANEL_OFFSET_Y, MENU_PANEL_WIDTH, MenuEntry, MenuView
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView


class _LobbyLayout(msgspec.Struct, frozen=True):
    scale: float
    panel_top_left: Vec2
    base_pos: Vec2
    back_pos: Vec2
    back_w: float


class NetworkLobbyPanelView(PanelMenuView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="Network Lobby",
            panel_offset=Vec2(-63.0, MENU_PANEL_OFFSET_Y),
            panel_height=278.0,
            back_action="open_play_game",
        )
        self._back_button = UiButtonState("Back", force_wide=False)
        self._error: str = ""

    def open(self) -> None:
        super().open()
        self._back_button = UiButtonState("Back", force_wide=False)
        self._error = ""

    def _begin_close_transition(self, action: str) -> None:
        if action == "open_play_game":
            runtime = self.state.network_runtime
            if runtime is not None:
                runtime.close()
            self.state.network_runtime = None
            self.state.network_in_lobby = False
            self.state.network_waiting_for_players = False
            self.state.network_expected_players = 1
            self.state.network_connected_players = 1
        super()._begin_close_transition(action)

    def update(self, dt: float) -> None:
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1
        dt_ms = int(min(dt, 0.1) * 1000.0)

        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)
            if self._timeline_ms >= self._timeline_max_ms:
                self.state.menu_sign_locked = True
                if (not self._panel_open_sfx_played) and (self.state.audio is not None):
                    play_sfx(self.state.audio, SfxId.UI_PANELCLICK)
                    self._panel_open_sfx_played = True

        enabled = self._timeline_ms >= PANEL_TIMELINE_START_MS
        self._update_back_button(dt_ms=dt_ms, enabled=enabled)
        if self._closing or self._timeline_ms < self._timeline_max_ms:
            return

        pending = self.state.pending_network_session
        runtime = self.state.network_runtime
        if pending is None or runtime is None:
            self._error = "Network runtime is not running."
            return

        error = str(runtime.error or "")
        if error:
            self._error = error
            return

        event = runtime.match_start()
        if event is None:
            return

        mode_raw = int(event.mode_id)
        try:
            mode_id = GameMode(mode_raw)
        except ValueError:
            self._error = f"Unsupported network mode id: {mode_raw}"
            return
        player_count = int(event.player_count)
        quest_level = event.quest_level

        self.state.network_in_lobby = True
        self.state.network_waiting_for_players = False
        self.state.network_expected_players = max(1, min(4, player_count))
        self.state.network_connected_players = int(self.state.network_expected_players)
        self.state.config.gameplay.player_count = int(self.state.network_expected_players)
        self.state.config.gameplay.mode = mode_id
        match mode_id:
            case GameMode.QUESTS:
                self.state.pending_quest_level = quest_level
            case _:
                pass

        match mode_id:
            case GameMode.SURVIVAL:
                action = "start_survival"
            case GameMode.RUSH:
                action = "start_rush"
            case GameMode.QUESTS:
                action = "start_quest"
            case _:
                self._error = f"Unsupported network mode id: {int(mode_id)}"
                return
        self._begin_close_transition(action)

    def _draw_entry(self, entry: MenuEntry) -> None:
        _ = entry

    def _layout(self) -> _LobbyLayout:
        panel_scale, _local_shift = self._menu_item_scale(0)
        panel_w = MENU_PANEL_WIDTH * panel_scale
        _, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
        )
        panel_top_left = (
            Vec2(
                self._panel_pos.x + slide_x,
                self._panel_pos.y + self._widescreen_y_shift,
            )
            + self._panel_offset * panel_scale
        )
        base_pos = panel_top_left + Vec2(212.0 * panel_scale, 40.0 * panel_scale)

        resources = require_runtime_resources(self.state)
        back_w = button_width(resources, self._back_button.label, scale=panel_scale, force_wide=self._back_button.force_wide)
        panel_h = float(self._panel_height) * panel_scale
        back_pos = panel_top_left + Vec2(panel_w - back_w - 22.0 * panel_scale, panel_h - 44.0 * panel_scale)

        return _LobbyLayout(
            scale=panel_scale,
            panel_top_left=panel_top_left,
            base_pos=base_pos,
            back_pos=back_pos,
            back_w=float(back_w),
        )

    def _update_back_button(self, *, dt_ms: int, enabled: bool) -> None:
        if not enabled:
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._begin_close_transition(self._back_action)
            return

        layout = self._layout()
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        self._back_button.enabled = True
        if button_update(
            self._back_button,
            pos=layout.back_pos,
            width=float(layout.back_w),
            dt_ms=float(dt_ms),
            mouse=mouse,
            click=bool(click),
        ):
            self._begin_close_transition(self._back_action)

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

        draw_small_text(font, "Network Lobby", base_pos, title_color)
        y = base_pos.y + float(font.cell_size) * title_scale + 6.0 * scale
        draw_small_text(font, "Waiting for peers to connect and ready up.", Vec2(base_pos.x, y), body_color)
        y += float(font.cell_size) * 0.9 * scale + 10.0 * scale

        pending = self.state.pending_network_session
        role = str(pending.role) if pending is not None else ""
        cfg = pending.config if pending is not None else None
        room_code = ""
        relay_text = "127.0.0.1:31993"
        if cfg is not None:
            endpoint = cfg.endpoint
            if isinstance(endpoint, LockstepEndpoint):
                room_code = "-"
                relay_text = f"{endpoint.host}:{int(endpoint.port)}"
            else:
                room_code = endpoint.room_code or "-"
                relay_text = f"{endpoint.relay_host}:{int(endpoint.relay_port)}"

        runtime: RollbackRuntime | LockstepRuntime | None = self.state.network_runtime
        lobby_state: LobbyState | RoomState | None = runtime.lobby_state() if runtime is not None else None
        if isinstance(lobby_state, RoomState):
            candidate = lobby_state.room_code
            if candidate:
                room_code = candidate

        session_id = str(lobby_state.session_id) if lobby_state is not None else ""
        expected = int(lobby_state.player_count) if lobby_state is not None else int(self.state.network_expected_players)
        expected = max(1, min(4, int(expected)))
        slots = lobby_state.slots if lobby_state is not None else None
        if isinstance(slots, list):
            connected = sum(1 for slot in slots if slot.connected)
        else:
            connected = int(self.state.network_connected_players)
        connected = max(0, min(4, int(connected)))

        dots = "." * int((self._cursor_pulse_time * 2.5) % 4)
        connected_text = f"{connected}/{expected}{dots}"
        role_label = "Host" if role == "host" else "Client"
        code_text = room_code or "-"

        label_w = max(
            measure_small_text_width(font, "Connected:"),
            measure_small_text_width(font, "Role:"),
            measure_small_text_width(font, "Code:"),
            measure_small_text_width(font, "Address:"),
            measure_small_text_width(font, "Session:"),
        )
        value_x = base_pos.x + label_w + 10.0 * scale
        line_h = float(font.cell_size) * text_scale + 3.0 * scale

        draw_small_text(font, "Connected:", Vec2(base_pos.x, y), label_color)
        draw_small_text(font, connected_text, Vec2(value_x, y), value_color)
        y += line_h

        draw_small_text(font, "Role:", Vec2(base_pos.x, y), label_color)
        draw_small_text(font, role_label, Vec2(value_x, y), value_color)
        y += line_h

        draw_small_text(font, "Code:", Vec2(base_pos.x, y), label_color)
        draw_small_text(font, code_text, Vec2(value_x, y), value_color)
        y += line_h

        draw_small_text(font, "Address:", Vec2(base_pos.x, y), label_color)
        draw_small_text(font, relay_text, Vec2(value_x, y), value_color)
        y += line_h

        if session_id:
            draw_small_text(font, "Session:", Vec2(base_pos.x, y), label_color)
            draw_small_text(font, session_id, Vec2(value_x, y), rl.Color(155, 175, 200, 255))
            y += line_h

        if isinstance(slots, list) and slots:
            y += 8.0 * scale
            draw_small_text(font, "Slots:", Vec2(base_pos.x, y), rl.Color(200, 200, 210, 255))
            y += line_h * 0.9

            col_slot_x = base_pos.x
            col_name_x = base_pos.x + 44.0 * scale
            col_state_x = base_pos.x + 186.0 * scale
            row_h = float(font.cell_size) * text_scale + 2.0 * scale
            for slot in slots[:4]:
                label = "host" if slot.is_host else (slot.peer_name or "peer")
                state = "READY" if slot.ready else ("CONNECTED" if slot.connected else "EMPTY")
                state_color = rl.Color(160, 220, 160, 255) if slot.ready else rl.Color(210, 210, 210, 255)

                draw_small_text(font, f"[{int(slot.slot_index)}]", Vec2(col_slot_x, y), value_color)
                draw_small_text(font, label, Vec2(col_name_x, y), value_color)
                draw_small_text(font, state, Vec2(col_state_x, y), state_color)
                y += row_h

        if self._error:
            y += 8.0 * scale
            draw_small_text(font, self._error, Vec2(base_pos.x, y), rl.Color(240, 90, 90, 255))
            y += line_h

        if debug_enabled():
            y += 10.0 * scale
            draw_small_text(font, "Debug:", Vec2(base_pos.x, y), rl.Color(232, 197, 117, 255))
            y += line_h
            draw_small_text(font, f"logs: {self.state.base_dir!s}/logs/lan/", Vec2(base_pos.x, y), rl.Color(232, 197, 117, 255))

        button_draw(
            resources,
            self._back_button,
            pos=layout.back_pos,
            width=float(layout.back_w),
            scale=scale,
        )
