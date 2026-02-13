from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer

from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ..assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ..menu import (
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MENU_SCALE_SMALL_THRESHOLD,
    MENU_SIGN_HEIGHT,
    MENU_SIGN_OFFSET_X,
    MENU_SIGN_OFFSET_Y,
    MENU_SIGN_POS_X_PAD,
    MENU_SIGN_POS_Y,
    MENU_SIGN_POS_Y_SMALL,
    MENU_SIGN_WIDTH,
    UI_SHADOW_OFFSET,
    MenuView,
    _draw_menu_cursor,
    ensure_menu_ground,
    menu_ground_camera,
)
from ..transitions import _draw_screen_fade
from ..types import GameState
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS


# Shared panel layout (state_14/15/16 in the oracle): tall left panel + short right panel.
LEFT_PANEL_POS_X = -119.0
LEFT_PANEL_POS_Y = 185.0
LEFT_PANEL_HEIGHT = 378.0

RIGHT_PANEL_POS_X = 609.0
RIGHT_PANEL_POS_Y = 200.0
RIGHT_PANEL_HEIGHT = 254.0


class _DatabaseBaseView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._small_font: SmallFontData | None = None
        self._button_textures: UiButtonTextureSet | None = None

        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action: str | None = None
        self._pending_action: str | None = None
        self._action: str | None = None

        self._back_button = UiButtonState("Back", force_wide=False)

    def open(self) -> None:
        layout_w = float(self._state.config.screen_width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._assets = load_menu_assets(self._state)
        self._ground = None if self._state.pause_background is not None else ensure_menu_ground(self._state)
        self._small_font = None
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._action = None

        cache = _ensure_texture_cache(self._state)
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)
        self._back_button = UiButtonState("Back", force_wide=False)

        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_panelclick", rng=self._state.rng)

    def close(self) -> None:
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None
        self._button_textures = None
        self._assets = None
        self._ground = None
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._action = None

    def take_action(self) -> str | None:
        if self._pending_action is not None:
            action = self._pending_action
            self._pending_action = None
            self._closing = False
            self._close_action = None
            self._timeline_ms = self._timeline_max_ms
            return action
        action = self._action
        self._action = None
        return action

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

    def _panel_top_left(self, *, pos: Vec2, scale: float) -> Vec2:
        return Vec2(
            pos.x + MENU_PANEL_OFFSET_X * scale,
            pos.y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _draw_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        sign = assets.sign
        screen_w = float(self._state.config.screen_width)
        sign_scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        sign_pos = Vec2(
            screen_w + MENU_SIGN_POS_X_PAD,
            MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL,
        )
        sign_w = MENU_SIGN_WIDTH * sign_scale
        sign_h = MENU_SIGN_HEIGHT * sign_scale
        offset_x = MENU_SIGN_OFFSET_X * sign_scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * sign_scale
        rotation_deg = 0.0
        fx_detail = self._state.config.fx_detail(level=0, default=False)
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(sign_pos.x + UI_SHADOW_OFFSET, sign_pos.y + UI_SHADOW_OFFSET, sign_w, sign_h),
                origin=rl.Vector2(-offset_x, -offset_y),
                rotation_deg=rotation_deg,
            )
        MenuView._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(sign_pos.x, sign_pos.y, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=rotation_deg,
            tint=rl.WHITE,
        )

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(float(dt), 0.1) * 1.1

        dt_ms = int(min(float(dt), 0.1) * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, int(self._timeline_ms + dt_ms))

        enabled = self._timeline_ms >= self._timeline_max_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._begin_close_transition("back_to_previous")
            return

        textures = self._button_textures
        if textures is None or (textures.button_md is None and textures.button_sm is None):
            return
        if not enabled:
            return

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        left_top_left = self._panel_top_left(pos=Vec2(LEFT_PANEL_POS_X, LEFT_PANEL_POS_Y), scale=scale)
        font = self._ensure_small_font()

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        self._update_content_interaction(left_top_left=left_top_left, scale=scale, mouse=mouse)

        back_pos = self._back_button_pos()
        back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
        if button_update(
            self._back_button,
            pos=left_top_left + back_pos * scale,
            width=back_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._begin_close_transition("back_to_previous")

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        pause_background = self._state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background()
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self._state))
        _draw_screen_fade(self._state)

        assets = self._assets
        if assets is None or assets.panel is None:
            return

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        fx_detail = self._state.config.fx_detail(level=0, default=False)

        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, left_slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        _angle_rad, right_slide_x = MenuView._ui_element_anim(
            self,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=1,
        )

        left_top_left = self._panel_top_left(pos=Vec2(LEFT_PANEL_POS_X, LEFT_PANEL_POS_Y), scale=scale)
        right_top_left = self._panel_top_left(pos=Vec2(RIGHT_PANEL_POS_X, RIGHT_PANEL_POS_Y), scale=scale)
        left_panel_top_left = left_top_left.offset(dx=float(left_slide_x))
        right_panel_top_left = right_top_left.offset(dx=float(right_slide_x))

        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(left_panel_top_left.x, left_panel_top_left.y, panel_w, LEFT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
        )
        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(right_panel_top_left.x, right_panel_top_left.y, panel_w, RIGHT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
            flip_x=True,
        )

        font = self._ensure_small_font()
        self._draw_contents(left_panel_top_left, right_panel_top_left, scale=scale, font=font)

        textures = self._button_textures
        if textures is not None and (textures.button_md is not None or textures.button_sm is not None):
            back_pos = self._back_button_pos()
            back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            button_draw(
                textures,
                font,
                self._back_button,
                pos=left_panel_top_left + back_pos * scale,
                width=back_w,
                scale=scale,
            )

        self._draw_sign()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def _back_button_pos(self) -> Vec2:
        raise NotImplementedError

    def _draw_contents(
        self,
        left_top_left: Vec2,
        right_top_left: Vec2,
        *,
        scale: float,
        font: SmallFontData,
    ) -> None:
        raise NotImplementedError

    def _update_content_interaction(self, *, left_top_left: Vec2, scale: float, mouse: rl.Vector2) -> None:
        return


class UnlockedWeaponsDatabaseView(_DatabaseBaseView):
    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._wicons_tex: rl.Texture | None = None
        self._weapon_ids: list[int] = []
        self._selected_weapon_id: int | None = None
        self._list_scroll_index: int = 0

    def open(self) -> None:
        super().open()
        self._weapon_ids = self._build_weapon_database_ids()
        self._selected_weapon_id = None
        self._list_scroll_index = 0
        cache = _ensure_texture_cache(self._state)
        self._wicons_tex = cache.get_or_load("ui_wicons", "ui/ui_wicons.jaz").texture

    def close(self) -> None:
        self._wicons_tex = None
        self._selected_weapon_id = None
        super().close()

    def _back_button_pos(self) -> Vec2:
        # state_15: ui_buttonSm bbox [270,507]..[352,539] => relative to left panel (-98,194): (368, 313)
        return Vec2(368.0, 313.0)

    def _draw_contents(self, left_top_left: Vec2, right_top_left: Vec2, *, scale: float, font: SmallFontData) -> None:
        left = left_top_left
        right = right_top_left
        text_scale = 1.0 * scale
        dim_color = rl.Color(255, 255, 255, int(255 * 0.7))
        text_color = rl.WHITE

        # state_15 title at (153,244) => relative to left panel (-98,194): (251,50)
        title_pos = left + Vec2(251.0 * scale, 50.0 * scale)
        title_text = "Unlocked Weapons Database"
        draw_small_text(
            font,
            title_text,
            title_pos,
            text_scale,
            rl.Color(255, 255, 255, 255),
        )
        title_w = measure_small_text_width(font, title_text, text_scale)
        # Decompile path draws a 1px outline strip under the title with alpha 0.5.
        rl.draw_rectangle_lines_ex(
            rl.Rectangle(
                title_pos.x,
                title_pos.y + 13.0 * scale,
                title_w,
                max(1.0, 1.0 * scale),
            ),
            1.0,
            rl.Color(255, 255, 255, int(255 * 0.5)),
        )

        weapon_ids = self._weapon_ids
        count = len(weapon_ids)
        weapon_label = "weapon" if count == 1 else "weapons"
        draw_small_text(
            font,
            f"{count} {weapon_label} in database",
            left + Vec2(210.0 * scale, 80.0 * scale),
            text_scale,
            dim_color,
        )
        draw_small_text(
            font,
            "Weapon",
            left + Vec2(210.0 * scale, 108.0 * scale),
            text_scale,
            text_color,
        )

        # Oracle frame: outer [114,322]-[364,486], inner [115,323]-[363,485].
        frame_x = left.x + 212.0 * scale
        frame_y = left.y + 128.0 * scale
        frame_w = 250.0 * scale
        frame_h = 164.0 * scale
        rl.draw_rectangle(int(round(frame_x)), int(round(frame_y)), int(round(frame_w)), int(round(frame_h)), rl.WHITE)
        rl.draw_rectangle(
            int(round(frame_x + 1.0 * scale)),
            int(round(frame_y + 1.0 * scale)),
            max(0, int(round(frame_w - 2.0 * scale))),
            max(0, int(round(frame_h - 2.0 * scale))),
            rl.BLACK,
        )

        # Oracle list widget is 10 rows tall.
        list_top_left = left + Vec2(218.0 * scale, 130.0 * scale)
        row_step = 16.0 * scale
        visible_rows = 10
        max_scroll = max(0, len(weapon_ids) - visible_rows)
        start = max(0, min(max_scroll, int(self._list_scroll_index)))
        end = min(len(weapon_ids), start + visible_rows)
        visible_weapon_ids = weapon_ids[start:end]
        for row, weapon_id in enumerate(visible_weapon_ids):
            name, _icon = self._weapon_label_and_icon(weapon_id)
            row_color = text_color if self._selected_weapon_id is not None and int(weapon_id) == int(self._selected_weapon_id) else dim_color
            draw_small_text(
                font,
                name,
                list_top_left.offset(dy=float(row) * row_step),
                text_scale,
                row_color,
            )

        if self._selected_weapon_id is None:
            return

        weapon_id = int(self._selected_weapon_id)
        name, icon_index = self._weapon_label_and_icon(weapon_id)
        weapon = self._weapon_entry(weapon_id)
        preserve_bugs = bool(getattr(self._state, "preserve_bugs", False))
        weapon_no_label = "wepno" if preserve_bugs else "weapon"
        draw_small_text(
            font,
            f"{weapon_no_label} #{weapon_id}",
            right + Vec2(240.0 * scale, 32.0 * scale),
            text_scale,
            rl.Color(255, 255, 255, int(255 * 0.4)),
        )
        draw_small_text(font, name, right + Vec2(50.0 * scale, 50.0 * scale), text_scale, text_color)
        if icon_index is not None:
            self._draw_wicon(icon_index, pos=right + Vec2(82.0 * scale, 82.0 * scale), scale=scale)

        if weapon is not None:
            rpm = self._weapon_rpm(weapon)
            reload_raw = getattr(weapon, "reload_time", None)
            clip_raw = getattr(weapon, "clip_size", None)
            reload_time = float(reload_raw) if isinstance(reload_raw, (int, float)) else None
            clip_size = int(clip_raw) if isinstance(clip_raw, (int, float)) else None
            ammo_class = int(getattr(weapon, "ammo_class", 0) or 0)
            firerate_label = "Firerate" if preserve_bugs else "Fire rate"
            if ammo_class == 1:
                firerate_text = f"{firerate_label}: n/a"
            elif rpm is not None:
                firerate_text = f"{firerate_label}: {rpm} rpm"
            else:
                firerate_text = None
            if firerate_text is not None:
                draw_small_text(font, firerate_text, right + Vec2(66.0 * scale, 128.0 * scale), text_scale, text_color)
            if reload_time is not None:
                draw_small_text(
                    font,
                    f"Reload time: {reload_time:.1f} secs",
                    right + Vec2(66.0 * scale, 146.0 * scale),
                    text_scale,
                    text_color,
                )
            if clip_size is not None:
                draw_small_text(
                    font,
                    f"Clip size: {clip_size}",
                    right + Vec2(66.0 * scale, 164.0 * scale),
                    text_scale,
                    text_color,
                )

    def _update_content_interaction(self, *, left_top_left: Vec2, scale: float, mouse: rl.Vector2) -> None:
        weapon_ids = self._weapon_ids
        if not weapon_ids:
            self._selected_weapon_id = None
            self._list_scroll_index = 0
            return

        visible_rows = 10
        max_scroll = max(0, len(weapon_ids) - visible_rows)
        mouse_wheel = int(rl.get_mouse_wheel_move())
        if mouse_wheel:
            self._list_scroll_index = max(0, min(max_scroll, int(self._list_scroll_index) - mouse_wheel))
        start = max(0, min(max_scroll, int(self._list_scroll_index)))
        end = min(len(weapon_ids), start + visible_rows)
        row_count = end - start
        if row_count <= 0:
            self._selected_weapon_id = None
            return

        row_step = 16.0 * scale
        list_hit_x = left_top_left.x + 214.0 * scale
        list_hit_y = left_top_left.y + 128.0 * scale
        list_hit_w = 246.0 * scale
        list_hit_h = min(160.0 * scale, row_step * float(row_count))
        if (
            list_hit_x <= mouse.x < list_hit_x + list_hit_w
            and list_hit_y <= mouse.y < list_hit_y + list_hit_h
        ):
            list_text_top = left_top_left.y + 130.0 * scale
            row = int((mouse.y - list_text_top) // row_step)
            if 0 <= row < row_count:
                self._selected_weapon_id = int(weapon_ids[start + row])
                return
        self._selected_weapon_id = None

    def _build_weapon_database_ids(self) -> list[int]:
        try:
            from ...weapons import WEAPON_TABLE, WeaponId
        except Exception:
            return []

        available: list[bool] | None = None
        weapon_refresh_available: Callable[..., None] | None = None
        try:
            from ...gameplay import WEAPON_COUNT_SIZE
            from ...weapon_runtime import (
                weapon_refresh_available as refresh_available,
            )
            weapon_refresh_available = cast(Callable[..., None], refresh_available)
        except Exception:
            WEAPON_COUNT_SIZE = max(int(entry.weapon_id) for entry in WEAPON_TABLE) + 1

        if weapon_refresh_available is not None:
            class _Stub:
                status: object | None
                game_mode: int
                demo_mode_active: bool
                weapon_available: list[bool]
                _weapon_available_game_mode: int
                _weapon_available_unlock_index: int
                _weapon_available_unlock_index_full: int

            stub = _Stub()
            stub.status = self._state.status
            stub.game_mode = self._state.config.game_mode
            stub.demo_mode_active = bool(getattr(self._state, "demo_enabled", False))
            stub.weapon_available = [False] * int(WEAPON_COUNT_SIZE)
            stub._weapon_available_game_mode = -1
            stub._weapon_available_unlock_index = -1
            stub._weapon_available_unlock_index_full = -1
            try:
                weapon_refresh_available(stub)
                available = stub.weapon_available
            except Exception:
                available = None

        status = self._state.status
        used: list[int] = []
        for weapon in WEAPON_TABLE:
            if weapon.name is None:
                continue
            weapon_id = int(weapon.weapon_id)
            include = False
            if available is not None:
                if 0 <= weapon_id < len(available):
                    include = bool(available[weapon_id])
            else:
                if weapon_id == int(WeaponId.PISTOL):
                    include = True
                else:
                    try:
                        include = bool(status.weapon_usage_count(weapon_id) != 0)
                    except Exception:
                        include = False
            if include:
                used.append(weapon_id)
        used.sort()
        return used

    def _weapon_entry(self, weapon_id: int) -> object | None:
        try:
            from ...weapons import WEAPON_BY_ID
        except Exception:
            return None
        return WEAPON_BY_ID.get(int(weapon_id))

    def _weapon_rpm(self, weapon: object) -> int | None:
        try:
            cooldown = getattr(weapon, "shot_cooldown", None)
            if cooldown is None:
                return None
            cooldown = float(cooldown)
        except Exception:
            return None
        if cooldown <= 0.0:
            return None
        return int(60.0 / cooldown)

    def _draw_wicon(self, icon_index: int, *, pos: Vec2, scale: float) -> None:
        tex = self._wicons_tex
        if tex is None:
            return
        idx = int(icon_index)
        if idx < 0 or idx > 31:
            return
        grid = 8
        cell_w = float(tex.width) / float(grid)
        cell_h = float(tex.height) / float(grid)
        frame = idx * 2
        src_x = float(frame % grid) * cell_w
        src_y = float(frame // grid) * cell_h
        icon_w = cell_w * 2.0
        icon_h = cell_h
        rl.draw_texture_pro(
            tex,
            rl.Rectangle(src_x, src_y, icon_w, icon_h),
            rl.Rectangle(pos.x, pos.y, icon_w * scale, icon_h * scale),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )

    def _weapon_label_and_icon(self, weapon_id: int) -> tuple[str, int | None]:
        from ...weapons import WEAPON_BY_ID, weapon_display_name

        weapon = WEAPON_BY_ID.get(int(weapon_id))
        if weapon is None:
            return f"Weapon {int(weapon_id)}", None
        name = weapon_display_name(
            int(weapon.weapon_id),
            preserve_bugs=bool(getattr(self._state, "preserve_bugs", False)),
        )
        return name, weapon.icon_index


class UnlockedPerksDatabaseView(_DatabaseBaseView):
    _VISIBLE_ROWS = 10
    _LIST_WIDTH = 250.0
    _LIST_FRAME_X = 212.0
    _LIST_FRAME_Y = 126.0
    _LIST_ROW_HEIGHT = 16.0
    _LIST_TEXT_X = 218.0
    _LIST_TEXT_Y = 128.0
    _DESC_WRAP_WIDTH_PX = 256.0

    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._perk_ids: list[int] = []
        self._list_scroll_index: int = 0
        self._selected_row_index: int = 0
        self._hovered_row_index: int = -1
        self._nav_focus_index: int = 0
        self._scroll_drag_active: bool = False
        self._scroll_drag_offset: float = 0.0
        self._wrapped_desc_cache: dict[tuple[int, int, int], str] = {}

    def open(self) -> None:
        super().open()
        self._perk_ids = self._build_perk_database_ids()
        self._hovered_row_index = -1
        self._scroll_drag_active = False
        self._scroll_drag_offset = 0.0
        self._wrapped_desc_cache.clear()
        if not self._perk_ids:
            self._list_scroll_index = 0
            self._selected_row_index = 0
            self._nav_focus_index = 0
            return
        max_scroll = max(0, len(self._perk_ids) - self._VISIBLE_ROWS)
        self._list_scroll_index = max(0, min(max_scroll, int(self._list_scroll_index)))
        self._selected_row_index = max(0, int(self._selected_row_index))
        self._nav_focus_index = max(0, min(1, int(self._nav_focus_index)))

    def _back_button_pos(self) -> Vec2:
        # state_16: ui_buttonSm bbox [258,509]..[340,541] => relative to left panel (-98,194): (356, 315)
        return Vec2(356.0, 315.0)

    def _draw_contents(self, left_top_left: Vec2, right_top_left: Vec2, *, scale: float, font: SmallFontData) -> None:
        left = left_top_left
        right = right_top_left
        text_scale = 1.0 * scale
        text_color = rl.WHITE
        dim_color = rl.Color(255, 255, 255, int(255 * 0.7))
        fx_toggle = self._fx_toggle()

        # state_16 title at (163,244) => relative to left panel (-98,194): (261,50)
        title_pos = left + Vec2(261.0 * scale, 50.0 * scale)
        title_text = "Unlocked Perks Database"
        draw_small_text(
            font,
            title_text,
            title_pos,
            text_scale,
            rl.Color(255, 255, 255, 255),
        )
        title_w = measure_small_text_width(font, title_text, text_scale)
        # Decompile path draws a 1px outline strip under the title with alpha 0.5.
        rl.draw_rectangle_lines_ex(
            rl.Rectangle(
                title_pos.x,
                title_pos.y + 13.0 * scale,
                title_w,
                max(1.0, 1.0 * scale),
            ),
            1.0,
            rl.Color(255, 255, 255, int(255 * 0.5)),
        )

        perk_ids = self._perk_ids
        count = len(perk_ids)
        perk_label = "perk" if count == 1 else "perks"
        draw_small_text(
            font,
            f"{count} {perk_label} in database",
            left + Vec2(210.0 * scale, 78.0 * scale),
            text_scale,
            dim_color,
        )
        draw_small_text(
            font,
            "Perks",
            left + Vec2(210.0 * scale, 106.0 * scale),
            text_scale,
            text_color,
        )

        frame_x = left.x + self._LIST_FRAME_X * scale
        frame_y = left.y + self._LIST_FRAME_Y * scale
        frame_w = self._LIST_WIDTH * scale
        frame_h = (self._VISIBLE_ROWS * self._LIST_ROW_HEIGHT + 4.0) * scale
        rl.draw_rectangle(int(round(frame_x)), int(round(frame_y)), int(round(frame_w)), int(round(frame_h)), rl.WHITE)
        rl.draw_rectangle(
            int(round(frame_x + 1.0 * scale)),
            int(round(frame_y + 1.0 * scale)),
            max(0, int(round(frame_w - 2.0 * scale))),
            max(0, int(round(frame_h - 2.0 * scale))),
            rl.BLACK,
        )

        max_scroll = max(0, len(perk_ids) - self._VISIBLE_ROWS)
        start = max(0, min(max_scroll, int(self._list_scroll_index)))
        end = min(len(perk_ids), start + self._VISIBLE_ROWS)
        list_top_left = left + Vec2(self._LIST_TEXT_X * scale, self._LIST_TEXT_Y * scale)
        row_step = self._LIST_ROW_HEIGHT * scale
        preserve_bugs = self._preserve_bugs()
        for row, perk_id in enumerate(perk_ids[start:end], start=0):
            list_index = start + row
            if list_index == self._hovered_row_index:
                row_alpha = 1.0
            elif list_index == self._selected_row_index:
                row_alpha = 0.9
            else:
                row_alpha = 0.7
            draw_small_text(
                font,
                self._perk_name(perk_id, fx_toggle=fx_toggle, preserve_bugs=preserve_bugs),
                list_top_left.offset(dy=float(row) * row_step),
                text_scale,
                rl.Color(255, 255, 255, int(255 * row_alpha)),
            )

        if count > self._VISIBLE_ROWS:
            # Native list draws a 1px scrollbar strip + draggable thumb.
            track_x, track_y, track_h, thumb_top, thumb_h, _scroll_span = self._scrollbar_geometry(
                left_top_left=left,
                scale=scale,
                count=count,
                start=start,
            )
            rl.draw_rectangle(
                int(round(track_x)),
                int(round(track_y)),
                max(1, int(round(1.0 * scale))),
                int(round(track_h)),
                rl.WHITE,
            )
            rl.draw_rectangle(
                int(round(track_x + 1.0 * scale)),
                int(round(thumb_top)),
                max(1, int(round(8.0 * scale))),
                max(1, int(round(thumb_h + 1.0 * scale))),
                rl.Color(255, 255, 255, int(255 * 0.8)),
            )
            rl.draw_rectangle(
                int(round(track_x + 2.0 * scale)),
                int(round(thumb_top + 1.0 * scale)),
                max(1, int(round(6.0 * scale))),
                max(1, int(round(max(1.0, thumb_h - 1.0 * scale)))),
                rl.Color(51, 204, 255, int(255 * 0.2)),
            )

        hovered_perk_id = self._hovered_perk_id()
        if hovered_perk_id is None:
            return
        perk_id = int(hovered_perk_id)
        perk_name = self._perk_name(perk_id, fx_toggle=fx_toggle, preserve_bugs=preserve_bugs)
        detail_anchor = right + Vec2(34.0 * scale, 72.0 * scale)
        perk_no_label = "perkno" if preserve_bugs else "perk"
        draw_small_text(
            font,
            f"{perk_no_label} #{perk_id}",
            detail_anchor + Vec2(190.0 * scale, -40.0 * scale),
            text_scale,
            rl.Color(255, 255, 255, int(255 * 0.4)),
        )
        name_w = measure_small_text_width(font, perk_name, text_scale)
        perk_name_pos = Vec2(detail_anchor.x + 128.0 * scale - name_w * 0.5, detail_anchor.y - 22.0 * scale)
        draw_small_text(font, perk_name, perk_name_pos, text_scale, text_color)
        rl.draw_rectangle_lines_ex(
            rl.Rectangle(
                perk_name_pos.x,
                perk_name_pos.y + 13.0 * scale,
                name_w,
                max(1.0, 1.0 * scale),
            ),
            1.0,
            rl.Color(255, 255, 255, int(255 * 0.5)),
        )

        desc_pos = detail_anchor + Vec2(16.0 * scale, 0.0)
        prereq_name = self._perk_prereq_name(perk_id, fx_toggle=fx_toggle, preserve_bugs=preserve_bugs)
        if prereq_name:
            draw_small_text(
                font,
                f"Requires: {prereq_name}",
                desc_pos,
                text_scale,
                rl.Color(255, 204, 204, int(255 * 0.8)),
            )
            desc_pos = desc_pos.offset(dy=18.0 * scale)

        wrapped_desc = self._prewrapped_perk_desc(perk_id, font, fx_toggle=fx_toggle)
        if wrapped_desc:
            draw_small_text(font, wrapped_desc, desc_pos, text_scale, dim_color)

    def _update_content_interaction(self, *, left_top_left: Vec2, scale: float, mouse: rl.Vector2) -> None:
        perk_ids = self._perk_ids
        count = len(perk_ids)
        self._hovered_row_index = -1
        if count <= 0:
            self._list_scroll_index = 0
            self._selected_row_index = 0
            self._nav_focus_index = 0
            self._scroll_drag_active = False
            return

        max_scroll = max(0, count - self._VISIBLE_ROWS)
        self._list_scroll_index = max(0, min(max_scroll, int(self._list_scroll_index)))
        self._selected_row_index = max(0, int(self._selected_row_index))

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self._nav_focus_index = max(0, int(self._nav_focus_index) - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._nav_focus_index = min(1, int(self._nav_focus_index) + 1)

        if self._nav_focus_index == 1:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
                self._list_scroll_index -= 1
            if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
                self._list_scroll_index += 1
            if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_UP):
                self._list_scroll_index -= self._VISIBLE_ROWS - 1
            if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
                self._list_scroll_index += self._VISIBLE_ROWS - 1

        list_hit_x = left_top_left.x + self._LIST_FRAME_X * scale
        list_hit_y = left_top_left.y + self._LIST_FRAME_Y * scale
        list_hit_w = self._LIST_WIDTH * scale
        list_hit_h = (self._VISIBLE_ROWS * self._LIST_ROW_HEIGHT + 4.0) * scale
        mouse_in_list = list_hit_x <= mouse.x < list_hit_x + list_hit_w and list_hit_y <= mouse.y < list_hit_y + list_hit_h
        if mouse_in_list:
            self._nav_focus_index = 1

        wheel = int(rl.get_mouse_wheel_move())
        if wheel and (mouse_in_list or self._nav_focus_index == 1):
            self._list_scroll_index -= wheel

        if count > self._VISIBLE_ROWS:
            start = max(0, min(max_scroll, int(self._list_scroll_index)))
            track_x, track_y, track_h, thumb_top, thumb_h, scroll_span = self._scrollbar_geometry(
                left_top_left=left_top_left,
                scale=scale,
                count=count,
                start=start,
            )
            thumb_x = track_x + 1.0 * scale
            thumb_w = 8.0 * scale
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
            in_track = track_x <= mouse.x < track_x + 10.0 * scale and track_y <= mouse.y < track_y + track_h
            in_thumb = thumb_x <= mouse.x < thumb_x + thumb_w and thumb_top <= mouse.y < thumb_top + thumb_h + 1.0 * scale

            if click and in_track:
                self._nav_focus_index = 1
                if in_thumb:
                    self._scroll_drag_active = True
                    self._scroll_drag_offset = float(mouse.y - thumb_top)
                else:
                    travel = max(1.0, track_h - 3.0 * scale - thumb_h)
                    target = float(mouse.y - track_y - 1.0 * scale - thumb_h * 0.5)
                    target = max(0.0, min(travel, target))
                    self._list_scroll_index = int(round((target / travel) * float(scroll_span)))
                    self._scroll_drag_active = True
                    self._scroll_drag_offset = thumb_h * 0.5

            if self._scroll_drag_active:
                if down:
                    travel = max(1.0, track_h - 3.0 * scale - thumb_h)
                    target = float(mouse.y - track_y - 1.0 * scale - self._scroll_drag_offset)
                    target = max(0.0, min(travel, target))
                    self._list_scroll_index = int(round((target / travel) * float(scroll_span)))
                else:
                    self._scroll_drag_active = False
        else:
            self._scroll_drag_active = False

        self._list_scroll_index = max(0, min(max_scroll, int(self._list_scroll_index)))

        start = max(0, min(max_scroll, int(self._list_scroll_index)))
        end = min(count, start + self._VISIBLE_ROWS)
        row_count = end - start
        if row_count > 0 and mouse_in_list:
            row_step = self._LIST_ROW_HEIGHT * scale
            list_text_top = left_top_left.y + self._LIST_TEXT_Y * scale
            row = int((mouse.y - list_text_top) // row_step)
            if 0 <= row < row_count:
                self._hovered_row_index = start + row
                if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
                    self._selected_row_index = self._hovered_row_index

        if self._nav_focus_index == 0 and (
            rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or rl.is_key_pressed(rl.KeyboardKey.KEY_KP_ENTER)
        ):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._begin_close_transition("back_to_previous")

    def _hovered_perk_id(self) -> int | None:
        if 0 <= int(self._hovered_row_index) < len(self._perk_ids):
            return int(self._perk_ids[int(self._hovered_row_index)])
        return None

    def _selected_perk_id(self) -> int | None:
        if 0 <= int(self._selected_row_index) < len(self._perk_ids):
            return int(self._perk_ids[int(self._selected_row_index)])
        return None

    def _scrollbar_geometry(
        self,
        *,
        left_top_left: Vec2,
        scale: float,
        count: int,
        start: int,
    ) -> tuple[float, float, float, float, float, int]:
        track_x = left_top_left.x + (self._LIST_FRAME_X + 240.0) * scale
        track_y = left_top_left.y + self._LIST_FRAME_Y * scale
        track_h = (self._VISIBLE_ROWS * self._LIST_ROW_HEIGHT + 4.0) * scale
        scroll_span = max(1, int(count) - self._VISIBLE_ROWS)
        thumb_h = (float(self._VISIBLE_ROWS) / float(count)) * track_h
        thumb_h = min(thumb_h, track_h - 3.0 * scale)
        thumb_top = track_y + 1.0 * scale + ((track_h - 3.0 * scale - thumb_h) / float(scroll_span)) * float(start)
        return track_x, track_y, track_h, thumb_top, thumb_h, scroll_span

    def _build_perk_database_ids(self) -> list[int]:
        from ...perks.availability import perks_rebuild_available
        from ...sim.state_types import PERK_COUNT_SIZE

        # Avoid spinning up a full GameplayState; perks_rebuild_available only needs these fields.
        class _Stub:
            status: object | None
            perk_available: list[bool]
            _perk_available_unlock_index: int

        stub = _Stub()
        stub.status = self._state.status
        stub.perk_available = [False] * int(PERK_COUNT_SIZE)
        stub._perk_available_unlock_index = -1
        perks_rebuild_available(stub)

        perk_ids = [idx for idx, available in enumerate(stub.perk_available) if available and idx > 0]
        perk_ids.sort()
        return perk_ids

    @staticmethod
    def _perk_name(perk_id: int, *, fx_toggle: int = 0, preserve_bugs: bool = False) -> str:
        from ...perks import perk_display_name

        return perk_display_name(
            int(perk_id),
            fx_toggle=int(fx_toggle),
            preserve_bugs=bool(preserve_bugs),
        )

    @staticmethod
    def _perk_desc(perk_id: int, *, fx_toggle: int = 0, preserve_bugs: bool = False) -> str:
        from ...perks import perk_display_description

        return perk_display_description(
            int(perk_id),
            fx_toggle=int(fx_toggle),
            preserve_bugs=bool(preserve_bugs),
        )

    @staticmethod
    def _perk_prereq_name(perk_id: int, *, fx_toggle: int = 0, preserve_bugs: bool = False) -> str | None:
        from ...perks import PERK_BY_ID, perk_display_name

        meta = PERK_BY_ID.get(int(perk_id))
        if meta is None:
            return None
        prereq = tuple(getattr(meta, "prereq", ()) or ())
        if not prereq:
            return None
        return perk_display_name(
            int(prereq[0]),
            fx_toggle=int(fx_toggle),
            preserve_bugs=bool(preserve_bugs),
        )

    def _preserve_bugs(self) -> bool:
        return bool(getattr(self._state, "preserve_bugs", False))

    def _fx_toggle(self) -> int:
        data = getattr(getattr(self._state, "config", None), "data", None)
        if not isinstance(data, dict):
            return 0
        return int(data.get("fx_toggle", 0) or 0)

    def _prewrapped_perk_desc(self, perk_id: int, font: SmallFontData, *, fx_toggle: int) -> str:
        key = (int(perk_id), int(fx_toggle), int(bool(self._preserve_bugs())))
        cached = self._wrapped_desc_cache.get(key)
        if cached is not None:
            return cached
        desc = self._perk_desc(perk_id, fx_toggle=fx_toggle, preserve_bugs=self._preserve_bugs())
        wrapped = self._wrap_small_text_native(
            font,
            desc,
            max_width_px=self._DESC_WRAP_WIDTH_PX,
            scale=1.0,
        )
        self._wrapped_desc_cache[key] = wrapped
        return wrapped

    @staticmethod
    def _wrap_small_text_native(font: SmallFontData, text: str, max_width_px: float, *, scale: float) -> str:
        wrapped = list(str(text))
        if not wrapped:
            return ""

        max_width = float(max_width_px)
        remaining = max_width
        i = 0
        while i < len(wrapped):
            ch = wrapped[i]
            if ch == "\r":
                i += 1
                continue
            if ch == "\n":
                remaining = max_width
                i += 1
                continue

            remaining -= measure_small_text_width(font, ch, float(scale))
            if remaining < 0.0:
                j = i
                while j > 0 and wrapped[j] not in {" ", "\n"}:
                    j -= 1
                if wrapped[j] == " ":
                    wrapped[j] = "\n"
                    i = j
                remaining = max_width
            i += 1

        return "".join(wrapped)
