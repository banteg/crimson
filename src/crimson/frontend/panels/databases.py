from __future__ import annotations

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
        self._action = None

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

    def _panel_top_left(self, *, pos_x: float, pos_y: float, scale: float) -> tuple[float, float]:
        x0 = pos_x + MENU_PANEL_OFFSET_X * scale
        y0 = pos_y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale
        return float(x0), float(y0)

    def _draw_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        sign = assets.sign
        screen_w = float(self._state.config.screen_width)
        sign_scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        pos_x = screen_w + MENU_SIGN_POS_X_PAD
        pos_y = MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL
        sign_w = MENU_SIGN_WIDTH * sign_scale
        sign_h = MENU_SIGN_HEIGHT * sign_scale
        offset_x = MENU_SIGN_OFFSET_X * sign_scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * sign_scale
        rotation_deg = 0.0
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(pos_x + UI_SHADOW_OFFSET, pos_y + UI_SHADOW_OFFSET, sign_w, sign_h),
                origin=rl.Vector2(-offset_x, -offset_y),
                rotation_deg=rotation_deg,
            )
        MenuView._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(pos_x, pos_y, sign_w, sign_h),
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
        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, int(self._timeline_ms + dt_ms))

        enabled = self._timeline_ms >= self._timeline_max_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "back_to_previous"
            return

        textures = self._button_textures
        if textures is None or (textures.button_md is None and textures.button_sm is None):
            return
        if not enabled:
            return

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        left_x0, left_y0 = self._panel_top_left(pos_x=LEFT_PANEL_POS_X, pos_y=LEFT_PANEL_POS_Y, scale=scale)

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)

        bx, by = self._back_button_pos()
        back_w = button_width(None, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
        if button_update(
            self._back_button,
            x=left_x0 + float(bx) * scale,
            y=left_y0 + float(by) * scale,
            width=back_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "back_to_previous"

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        pause_background = self._state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background()
        elif self._ground is not None:
            self._ground.draw(Vec2())
        _draw_screen_fade(self._state)

        assets = self._assets
        if assets is None or assets.panel is None:
            return

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))

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

        left_x0, left_y0 = self._panel_top_left(pos_x=LEFT_PANEL_POS_X, pos_y=LEFT_PANEL_POS_Y, scale=scale)
        right_x0, right_y0 = self._panel_top_left(pos_x=RIGHT_PANEL_POS_X, pos_y=RIGHT_PANEL_POS_Y, scale=scale)
        left_x0 += float(left_slide_x)
        right_x0 += float(right_slide_x)

        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(left_x0, left_y0, panel_w, LEFT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
        )
        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(right_x0, right_y0, panel_w, RIGHT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
        )

        font = self._ensure_small_font()
        self._draw_contents(left_x0, left_y0, right_x0, right_y0, scale=scale, font=font)

        textures = self._button_textures
        if textures is not None and (textures.button_md is not None or textures.button_sm is not None):
            bx, by = self._back_button_pos()
            back_w = button_width(None, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            button_draw(
                textures,
                font,
                self._back_button,
                x=left_x0 + float(bx) * scale,
                y=left_y0 + float(by) * scale,
                width=back_w,
                scale=scale,
            )

        self._draw_sign()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def _back_button_pos(self) -> tuple[float, float]:
        raise NotImplementedError

    def _draw_contents(
        self,
        left_x0: float,
        left_y0: float,
        right_x0: float,
        right_y0: float,
        *,
        scale: float,
        font: SmallFontData,
    ) -> None:
        raise NotImplementedError


class UnlockedWeaponsDatabaseView(_DatabaseBaseView):
    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._wicons_tex: rl.Texture2D | None = None
        self._weapon_ids: list[int] = []
        self._selected_weapon_id: int = 2

    def open(self) -> None:
        super().open()
        self._weapon_ids = self._build_weapon_database_ids()
        self._selected_weapon_id = 2 if 2 in self._weapon_ids else (self._weapon_ids[0] if self._weapon_ids else 2)

        if self._wicons_tex is not None:
            rl.unload_texture(self._wicons_tex)
            self._wicons_tex = None
        wicons_path = self._state.assets_dir / "crimson" / "ui" / "ui_wicons.png"
        if wicons_path.is_file():
            self._wicons_tex = rl.load_texture(str(wicons_path))

    def close(self) -> None:
        if self._wicons_tex is not None:
            rl.unload_texture(self._wicons_tex)
            self._wicons_tex = None
        super().close()

    def _back_button_pos(self) -> tuple[float, float]:
        # state_15: ui_buttonSm bbox [270,507]..[352,539] => relative to left panel (-98,194): (368, 313)
        return (368.0, 313.0)

    def _draw_contents(self, left_x0: float, left_y0: float, right_x0: float, right_y0: float, *, scale: float, font: SmallFontData) -> None:
        text_scale = 1.0 * scale
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        # state_15 title at (153,244) => relative to left panel (-98,194): (251,50)
        draw_small_text(
            font,
            "Unlocked Weapons Database",
            left_x0 + 251.0 * scale,
            left_y0 + 50.0 * scale,
            text_scale,
            rl.Color(255, 255, 255, 255),
        )

        weapon_ids = self._weapon_ids
        count = len(weapon_ids)
        weapon_label = "weapon" if count == 1 else "weapons"
        draw_small_text(
            font,
            f"{count} {weapon_label} in database",
            left_x0 + 210.0 * scale,
            left_y0 + 80.0 * scale,
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Weapon",
            left_x0 + 210.0 * scale,
            left_y0 + 108.0 * scale,
            text_scale,
            text_color,
        )

        # List items (oracle shows 9-row list widget; render the top slice for now).
        list_x = left_x0 + 218.0 * scale
        list_y0 = left_y0 + 130.0 * scale
        row_step = 16.0 * scale
        for row, weapon_id in enumerate(weapon_ids[:9]):
            name, _icon = self._weapon_label_and_icon(weapon_id)
            draw_small_text(font, name, list_x, list_y0 + float(row) * row_step, text_scale, text_color)

        weapon_id = int(self._selected_weapon_id)
        name, icon_index = self._weapon_label_and_icon(weapon_id)
        weapon = self._weapon_entry(weapon_id)
        draw_small_text(
            font,
            f"wepno #{weapon_id}",
            right_x0 + 240.0 * scale,
            right_y0 + 32.0 * scale,
            text_scale,
            text_color,
        )
        draw_small_text(font, name, right_x0 + 50.0 * scale, right_y0 + 50.0 * scale, text_scale, text_color)
        if icon_index is not None:
            self._draw_wicon(icon_index, x=right_x0 + 82.0 * scale, y=right_y0 + 82.0 * scale, scale=scale)

        if weapon is not None:
            rpm = self._weapon_rpm(weapon)
            reload_time = weapon.reload_time
            clip_size = weapon.clip_size
            if rpm is not None:
                draw_small_text(
                    font,
                    f"Firerate: {rpm} rpm",
                    right_x0 + 66.0 * scale,
                    right_y0 + 128.0 * scale,
                    text_scale,
                    text_color,
                )
            if reload_time is not None:
                draw_small_text(
                    font,
                    f"Reload time: {reload_time:g} secs",
                    right_x0 + 66.0 * scale,
                    right_y0 + 146.0 * scale,
                    text_scale,
                    text_color,
                )
            if clip_size is not None:
                draw_small_text(
                    font,
                    f"Clip size: {int(clip_size)}",
                    right_x0 + 66.0 * scale,
                    right_y0 + 164.0 * scale,
                    text_scale,
                    text_color,
                )

    def _build_weapon_database_ids(self) -> list[int]:
        try:
            from ...weapons import WEAPON_TABLE
        except Exception:
            return []
        status = self._state.status
        used: list[int] = []
        for weapon in WEAPON_TABLE:
            if weapon.name is None:
                continue
            weapon_id = int(weapon.weapon_id)
            try:
                if status.weapon_usage_count(weapon_id) != 0:
                    used.append(weapon_id)
            except Exception:
                continue
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

    def _draw_wicon(self, icon_index: int, *, x: float, y: float, scale: float) -> None:
        tex = self._wicons_tex
        if tex is None:
            return
        idx = int(icon_index)
        if idx < 0 or idx > 31:
            return
        cols = 4
        rows = 8
        icon_w = float(tex.width) / float(cols)
        icon_h = float(tex.height) / float(rows)
        src_x = float(idx % cols) * icon_w
        src_y = float(idx // cols) * icon_h
        rl.draw_texture_pro(
            tex,
            rl.Rectangle(src_x, src_y, icon_w, icon_h),
            rl.Rectangle(float(x), float(y), icon_w * scale, icon_h * scale),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )

    @staticmethod
    def _weapon_label_and_icon(weapon_id: int) -> tuple[str, int | None]:
        try:
            from ...weapons import WEAPON_BY_ID
        except Exception:
            WEAPON_BY_ID = {}
        weapon = WEAPON_BY_ID.get(int(weapon_id))
        if weapon is None:
            return f"Weapon {int(weapon_id)}", None
        name = weapon.name or f"weapon_{int(weapon.weapon_id)}"
        return name, weapon.icon_index


class UnlockedPerksDatabaseView(_DatabaseBaseView):
    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._perk_ids: list[int] = []
        self._selected_perk_id: int = 4

    def open(self) -> None:
        super().open()
        self._perk_ids = self._build_perk_database_ids()
        self._selected_perk_id = 4 if 4 in self._perk_ids else (self._perk_ids[0] if self._perk_ids else 4)

    def _back_button_pos(self) -> tuple[float, float]:
        # state_16: ui_buttonSm bbox [258,509]..[340,541] => relative to left panel (-98,194): (356, 315)
        return (356.0, 315.0)

    def _draw_contents(self, left_x0: float, left_y0: float, right_x0: float, right_y0: float, *, scale: float, font: SmallFontData) -> None:
        text_scale = 1.0 * scale
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        # state_16 title at (163,244) => relative to left panel (-98,194): (261,50)
        draw_small_text(
            font,
            "Unlocked Perks Database",
            left_x0 + 261.0 * scale,
            left_y0 + 50.0 * scale,
            text_scale,
            rl.Color(255, 255, 255, 255),
        )

        perk_ids = self._perk_ids
        count = len(perk_ids)
        perk_label = "perk" if count == 1 else "perks"
        draw_small_text(
            font,
            f"{count} {perk_label} in database",
            left_x0 + 210.0 * scale,
            left_y0 + 78.0 * scale,
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Perks",
            left_x0 + 210.0 * scale,
            left_y0 + 106.0 * scale,
            text_scale,
            text_color,
        )

        list_x = left_x0 + 218.0 * scale
        list_y0 = left_y0 + 128.0 * scale
        row_step = 16.0 * scale
        for row, perk_id in enumerate(perk_ids[:9]):
            draw_small_text(font, self._perk_name(perk_id), list_x, list_y0 + float(row) * row_step, text_scale, text_color)

        perk_id = int(self._selected_perk_id)
        perk_name = self._perk_name(perk_id)
        draw_small_text(
            font,
            f"perkno #{perk_id}",
            right_x0 + 224.0 * scale,
            right_y0 + 32.0 * scale,
            text_scale,
            text_color,
        )
        draw_small_text(font, perk_name, right_x0 + 93.0 * scale, right_y0 + 50.0 * scale, text_scale, text_color)

        desc_x = right_x0 + 50.0 * scale
        desc_y = right_y0 + 72.0 * scale
        max_w = float(rl.get_screen_width()) - desc_x - 4.0 * scale
        desc = self._perk_desc(perk_id)
        first_line = self._truncate_small_line(font, desc, max_w, scale=text_scale)
        if first_line:
            draw_small_text(font, first_line, desc_x, desc_y, text_scale, text_color)

    def _build_perk_database_ids(self) -> list[int]:
        try:
            from ...gameplay import PERK_COUNT_SIZE, perks_rebuild_available
        except Exception:
            return []

        # Avoid spinning up a full GameplayState; perks_rebuild_available only needs these fields.
        class _Stub:
            status: object | None
            perk_available: list[bool]
            _perk_available_unlock_index: int

        stub = _Stub()
        stub.status = self._state.status
        stub.perk_available = [False] * int(PERK_COUNT_SIZE)
        stub._perk_available_unlock_index = -1
        perks_rebuild_available(stub)  # type: ignore[arg-type]

        perk_ids = [idx for idx, available in enumerate(stub.perk_available) if available and idx > 0]
        perk_ids.sort()
        return perk_ids

    @staticmethod
    def _perk_name(perk_id: int) -> str:
        try:
            from ...perks import perk_display_name

            return perk_display_name(int(perk_id))
        except Exception:
            return f"Perk {int(perk_id)}"

    @staticmethod
    def _perk_desc(perk_id: int) -> str:
        try:
            from ...perks import perk_display_description

            return perk_display_description(int(perk_id))
        except Exception:
            return ""

    @staticmethod
    def _truncate_small_line(font: SmallFontData, text: str, max_width: float, *, scale: float) -> str:
        text = str(text).strip()
        if not text:
            return ""
        words = text.split()
        line = ""
        for word in words:
            candidate = word if not line else f"{line} {word}"
            if measure_small_text_width(font, candidate, float(scale)) <= float(max_width):
                line = candidate
                continue
            break
        return line
