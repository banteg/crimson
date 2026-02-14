from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2

from ...debug import debug_enabled
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ..menu import MENU_PANEL_OFFSET_Y, MENU_PANEL_WIDTH, MenuEntry, MenuView
from ..types import GameState
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView


@dataclass(frozen=True, slots=True)
class _LobbyLayout:
    scale: float
    panel_top_left: Vec2
    base_pos: Vec2
    back_pos: Vec2
    back_w: float


class LanLobbyPanelView(PanelMenuView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="LAN Lobby",
            panel_offset=Vec2(-63.0, MENU_PANEL_OFFSET_Y),
            panel_height=278.0,
            back_action="open_play_game",
        )
        self._small_font: SmallFontData | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._back_button = UiButtonState("Back", force_wide=False)
        self._error: str = ""

    def open(self) -> None:
        super().open()
        cache = self._ensure_cache()
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)
        self._back_button = UiButtonState("Back", force_wide=False)
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
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1
        dt_ms = int(min(dt, 0.1) * 1000.0)

        # Close transition (matches PanelMenuView).
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
                    play_sfx(self.state.audio, "sfx_ui_panelclick", rng=self.state.rng)
                    self._panel_open_sfx_played = True

        enabled = self._timeline_ms >= PANEL_TIMELINE_START_MS
        self._update_back_button(dt_ms=dt_ms, enabled=enabled)
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

    def _draw_entry(self, entry: MenuEntry) -> None:
        # Panels outside the main menu use in-panel back buttons instead of the classic menu item.
        _ = entry
        return

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self.state.assets_dir, missing_assets)
        return self._small_font

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

        # Content is anchored relative to the panel top-left so it scales/animates with the panel.
        base_pos = panel_top_left + Vec2(56.0 * panel_scale, 40.0 * panel_scale)

        font = self._ensure_small_font()
        back_w = button_width(font, self._back_button.label, scale=panel_scale, force_wide=self._back_button.force_wide)
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

        textures = self._button_textures
        if textures is None:
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
        font = self._ensure_small_font()
        scale = float(layout.scale)
        base_pos = layout.base_pos
        text_scale = 1.0 * scale

        title_scale = 1.2 * scale
        title_color = rl.Color(255, 255, 255, 255)
        body_color = rl.Color(190, 210, 230, 220)
        label_color = rl.Color(190, 190, 200, 230)
        value_color = rl.Color(225, 235, 247, 255)

        draw_small_text(font, "LAN Lobby", base_pos, title_scale, title_color)
        y = base_pos.y + float(font.cell_size) * title_scale + 6.0 * scale
        draw_small_text(
            font,
            "Waiting for peers to connect and ready up.",
            Vec2(base_pos.x, y),
            0.9 * scale,
            body_color,
        )
        y += float(font.cell_size) * 0.9 * scale + 10.0 * scale

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
        connected_text = f"{connected}/{expected}{dots}"
        role_label = "Host" if role == "host" else "Client"
        addr_text = f"{bind_host}:{port}" if role == "host" else f"{host_ip}:{port}"
        addr_label = "Bind:" if role == "host" else "Host:"

        label_w = max(
            measure_small_text_width(font, "Connected:", text_scale),
            measure_small_text_width(font, "Role:", text_scale),
            measure_small_text_width(font, addr_label, text_scale),
            measure_small_text_width(font, "Session:", text_scale),
        )
        value_x = base_pos.x + label_w + 10.0 * scale
        line_h = float(font.cell_size) * text_scale + 3.0 * scale

        draw_small_text(font, "Connected:", Vec2(base_pos.x, y), text_scale, label_color)
        draw_small_text(font, connected_text, Vec2(value_x, y), text_scale, value_color)
        y += line_h

        draw_small_text(font, "Role:", Vec2(base_pos.x, y), text_scale, label_color)
        draw_small_text(font, role_label, Vec2(value_x, y), text_scale, value_color)
        y += line_h

        draw_small_text(font, addr_label, Vec2(base_pos.x, y), text_scale, label_color)
        draw_small_text(font, addr_text, Vec2(value_x, y), text_scale, value_color)
        y += line_h

        if session_id:
            draw_small_text(font, "Session:", Vec2(base_pos.x, y), text_scale, label_color)
            draw_small_text(font, session_id, Vec2(value_x, y), text_scale, rl.Color(155, 175, 200, 255))
            y += line_h

        if isinstance(slots, list) and slots:
            y += 8.0 * scale
            draw_small_text(font, "Slots:", Vec2(base_pos.x, y), text_scale, rl.Color(200, 200, 210, 255))
            y += line_h * 0.9

            col_slot_x = base_pos.x
            col_name_x = base_pos.x + 44.0 * scale
            col_state_x = base_pos.x + 186.0 * scale
            row_h = float(font.cell_size) * text_scale + 2.0 * scale
            for slot in slots[:4]:
                idx = int(getattr(slot, "slot_index", -1))
                is_host = bool(getattr(slot, "is_host", False))
                ready = bool(getattr(slot, "ready", False))
                conn = bool(getattr(slot, "connected", False))
                name = str(getattr(slot, "peer_name", "") or "")
                label = "host" if is_host else (name or "peer")
                state = "READY" if ready else ("CONNECTED" if conn else "EMPTY")
                state_color = rl.Color(160, 220, 160, 255) if ready else rl.Color(210, 210, 210, 255)

                draw_small_text(font, f"[{idx}]", Vec2(col_slot_x, y), text_scale, value_color)
                draw_small_text(font, label, Vec2(col_name_x, y), text_scale, value_color)
                draw_small_text(font, state, Vec2(col_state_x, y), text_scale, state_color)
                y += row_h

        if self._error:
            y += 8.0 * scale
            draw_small_text(font, self._error, Vec2(base_pos.x, y), text_scale, rl.Color(240, 90, 90, 255))
            y += line_h

        if debug_enabled():
            y += 10.0 * scale
            base_dir = getattr(self.state, "base_dir", None)
            draw_small_text(font, "Debug:", Vec2(base_pos.x, y), text_scale, rl.Color(232, 197, 117, 255))
            y += line_h
            if base_dir is not None:
                draw_small_text(
                    font,
                    f"logs: {str(base_dir)}/logs/lan/",
                    Vec2(base_pos.x, y),
                    text_scale,
                    rl.Color(232, 197, 117, 255),
                )

        textures = self._button_textures
        if textures is not None:
            button_draw(
                textures,
                font,
                self._back_button,
                pos=layout.back_pos,
                width=float(layout.back_w),
                scale=scale,
            )
