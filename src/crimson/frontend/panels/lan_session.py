from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2

from ...game.types import LanSessionConfig, LanSessionMode, PendingLanSession
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ...ui.text_input import poll_text_input
from ..menu import MENU_PANEL_OFFSET_Y, MENU_PANEL_WIDTH, MenuEntry, MenuView
from ..types import GameState
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView


@dataclass(frozen=True, slots=True)
class _SessionLayout:
    scale: float
    panel_top_left: Vec2
    base_pos: Vec2
    back_pos: Vec2
    back_w: float


class LanSessionPanelView(PanelMenuView):
    _MODES: tuple[LanSessionMode, ...] = ("survival", "rush", "quests")

    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="LAN Session",
            panel_offset=Vec2(-63.0, MENU_PANEL_OFFSET_Y),
            panel_height=278.0,
            back_action="open_play_game",
        )
        self._small_font: SmallFontData | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._back_button = UiButtonState("Back", force_wide=False)

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

        cache = self._ensure_cache()
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)
        self._back_button = UiButtonState("Back", force_wide=False)

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

    def _layout(self) -> _SessionLayout:
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
        base_pos = panel_top_left + Vec2(56.0 * panel_scale, 40.0 * panel_scale)

        font = self._ensure_small_font()
        back_w = button_width(font, self._back_button.label, scale=panel_scale, force_wide=self._back_button.force_wide)
        panel_h = float(self._panel_height) * panel_scale
        back_pos = panel_top_left + Vec2(panel_w - back_w - 22.0 * panel_scale, panel_h - 44.0 * panel_scale)

        return _SessionLayout(
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
                    preserve_bugs=False,
                ),
                auto_start=False,
            )

        self.state.pending_lan_session = pending
        self._begin_close_transition(self._mode_start_action(mode))

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
        active_color = rl.Color(232, 197, 117, 255)

        draw_small_text(font, "LAN Session", base_pos, title_scale, title_color)
        y = base_pos.y + float(font.cell_size) * title_scale + 6.0 * scale
        draw_small_text(
            font,
            "Host or join a LAN lockstep session.",
            Vec2(base_pos.x, y),
            0.9 * scale,
            body_color,
        )
        y += float(font.cell_size) * 0.9 * scale + 10.0 * scale

        mode = self._current_mode()
        role_label = "Host" if self._role == "host" else "Join"
        where_label = "Bind:" if self._role == "host" else "Host:"
        where_value = self._bind_host if self._role == "host" else self._host_ip

        label_w = max(
            measure_small_text_width(font, "Role:", text_scale),
            measure_small_text_width(font, "Mode:", text_scale),
            measure_small_text_width(font, "Players:", text_scale),
            measure_small_text_width(font, where_label, text_scale),
            measure_small_text_width(font, "Port:", text_scale),
            measure_small_text_width(font, "Quest:", text_scale),
        )
        value_x = base_pos.x + label_w + 10.0 * scale
        line_h = float(font.cell_size) * text_scale + 3.0 * scale

        draw_small_text(font, "Role:", Vec2(base_pos.x, y), text_scale, label_color)
        draw_small_text(font, role_label, Vec2(value_x, y), text_scale, value_color)
        y += line_h

        draw_small_text(font, "Mode:", Vec2(base_pos.x, y), text_scale, label_color)
        draw_small_text(font, str(mode), Vec2(value_x, y), text_scale, value_color)
        y += line_h

        draw_small_text(font, "Players:", Vec2(base_pos.x, y), text_scale, label_color)
        draw_small_text(font, str(self._player_count), Vec2(value_x, y), text_scale, value_color)
        y += line_h

        draw_small_text(font, where_label, Vec2(base_pos.x, y), text_scale, label_color)
        where_tint = active_color if self._active_field in {"bind_host", "host_ip"} else value_color
        draw_small_text(font, where_value or "-", Vec2(value_x, y), text_scale, where_tint)
        y += line_h

        draw_small_text(font, "Port:", Vec2(base_pos.x, y), text_scale, label_color)
        port_tint = active_color if self._active_field == "port" else value_color
        draw_small_text(font, self._port_text or "-", Vec2(value_x, y), text_scale, port_tint)
        y += line_h

        if mode == "quests":
            draw_small_text(font, "Quest:", Vec2(base_pos.x, y), text_scale, label_color)
            quest_tint = active_color if self._active_field == "quest_level" else value_color
            draw_small_text(font, self._quest_level or "-", Vec2(value_x, y), text_scale, quest_tint)
            y += line_h

        y += 4.0 * scale
        draw_small_text(
            font,
            "TAB: role   M: mode   [ / ]: players   H/P/L: edit   ENTER: continue",
            Vec2(base_pos.x, y),
            0.85 * scale,
            rl.Color(160, 160, 170, 220),
        )

        if self._error:
            y += float(font.cell_size) * 0.9 * scale + 6.0 * scale
            draw_small_text(font, self._error, Vec2(base_pos.x, y), text_scale, rl.Color(240, 90, 90, 255))

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
