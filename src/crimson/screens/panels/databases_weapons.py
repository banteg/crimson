from __future__ import annotations

from typing import TYPE_CHECKING

from crimson.game_states import GameStateId
from grim import canvas
from grim.assets import TextureId
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ...ui.scrollbar import ui_scrollbar_draw, ui_scrollbar_update
from ..assets import require_runtime_resources
from ..high_scores_layout import weapons_db_right_detail_x_shift
from .databases_base import _DatabaseBaseView

if TYPE_CHECKING:
    from ...weapons import Weapon


class UnlockedWeaponsDatabaseView(_DatabaseBaseView):
    game_state = GameStateId.WEAPON_DATABASE

    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._weapon_ids: list[int] = []
        # The weapon under the mouse, or the list's keyboard row while it is focused.
        self._selected_weapon_id: int | None = None

    def open(self) -> None:
        super().open()
        self._weapon_ids = self._build_weapon_database_ids()
        self._selected_weapon_id = None
        self.list_scroll.items = [self._weapon_label_and_icon(weapon_id)[0] for weapon_id in self._weapon_ids]
        self.list_scroll.scroll_offset = 0.0
        self.list_scroll.hovered_index = -1

    def close(self) -> None:
        self._selected_weapon_id = None
        super().close()

    def _back_button_pos(self) -> Vec2:
        # state_15: ui_buttonSm bbox [270,507]..[352,539] => relative to left panel (-98,194): (368, 313)
        return Vec2(368.0, 313.0)

    def _draw_contents(self, left_top_left: Vec2, right_top_left: Vec2, *, font: SmallFontData) -> None:
        left = left_top_left
        right = right_top_left
        detail_shift_x = weapons_db_right_detail_x_shift(float(self.state.config.display.width))
        detail_top_left = right + Vec2(detail_shift_x, 0.0)
        dim_color = rl.Color(255, 255, 255, int(255 * 0.7))
        text_color = rl.WHITE

        # state_15 title at (153,244) => relative to left panel (-98,194): (251,50)
        title_pos = left + Vec2(251.0, 50.0)
        title_text = "Unlocked Weapons Database"
        draw_small_text(font, title_text, title_pos, rl.Color(255, 255, 255, 255))
        title_w = measure_small_text_width(font, title_text)
        # Decompile path draws a 1px outline strip under the title with alpha 0.5.
        rl.draw_rectangle_lines_ex(
            rl.Rectangle(
                title_pos.x,
                title_pos.y + 13.0,
                title_w,
                1.0,
            ),
            1.0,
            rl.Color(255, 255, 255, int(255 * 0.5)),
        )

        weapon_ids = self._weapon_ids
        count = len(weapon_ids)
        weapon_label = "weapon" if count == 1 else "weapons"
        draw_small_text(font, f"{count} {weapon_label} in database", left + Vec2(210.0, 80.0), dim_color)
        draw_small_text(font, "Weapon", left + Vec2(210.0, 108.0), text_color)

        ui_scrollbar_draw(
            font, self.state.focus, self.list_scroll, left + Vec2(212.0, 128.0), mouse=Vec2.from_xy(canvas.mouse_position()),
        )

        if self._selected_weapon_id is None:
            return

        weapon_id = int(self._selected_weapon_id)
        name, icon_index = self._weapon_label_and_icon(weapon_id)
        weapon = self._weapon_entry(weapon_id)
        weapon_no_label = "wepno"
        draw_small_text(font, f"{weapon_no_label} #{weapon_id}", detail_top_left + Vec2(240.0, 32.0), rl.Color(255, 255, 255, int(255 * 0.4)))
        draw_small_text(font, name, detail_top_left + Vec2(50.0, 50.0), text_color)
        if icon_index is not None:
            self._draw_wicon(icon_index, pos=detail_top_left + Vec2(82.0, 82.0))

        reload_time = weapon.reload_time
        clip_size = weapon.clip_size
        ammo_class = int(weapon.ammo_class or 0)
        firerate_label = "Firerate"
        if ammo_class == 1:
            firerate_text = f"{firerate_label}: n/a"
        else:
            firerate_text = f"{firerate_label}: {self._weapon_rpm(weapon)} rpm"
        draw_small_text(font, firerate_text, detail_top_left + Vec2(66.0, 128.0), text_color)
        draw_small_text(font, f"Reload time: {reload_time:.1f} secs", detail_top_left + Vec2(66.0, 146.0), text_color)
        draw_small_text(font, f"Clip size: {clip_size}", detail_top_left + Vec2(66.0, 164.0), text_color)

    def _update_content_interaction(self, *, left_top_left: Vec2, mouse: rl.Vector2) -> None:
        bar = self.list_scroll
        ui_scrollbar_update(
            self.state.focus,
            bar,
            left_top_left + Vec2(212.0, 128.0),
            mouse=Vec2.from_xy(mouse),
            click=rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT),
            down=rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT),
            wheel=rl.get_mouse_wheel_move(),
            cursor=True,
        )
        self._selected_weapon_id = None
        if bar.hovered_index != -1:
            self._selected_weapon_id = self._weapon_ids[bar.hovered_index]
        elif bar.keyed:
            self._selected_weapon_id = self._weapon_ids[bar.selected_index]

    def _build_weapon_database_ids(self) -> list[int]:
        from ...game_modes import GameMode
        from ...weapon_runtime.availability import build_weapon_availability
        from ...weapon_usage import weapon_usage_slot_for_weapon_id
        from ...weapons import WEAPON_TABLE, WeaponId

        available = build_weapon_availability(
            status=self.state.status,
            game_mode=GameMode(self.state.config.gameplay.mode),
        )
        status = self.state.status
        used: list[int] = []
        for weapon in WEAPON_TABLE:
            weapon_id = int(weapon.weapon_id)
            include = False
            if 0 <= weapon_id < len(available):
                include = bool(available[weapon_id])
            if not include:
                if weapon_id == WeaponId.PISTOL:
                    include = True
                else:
                    usage_slot = weapon_usage_slot_for_weapon_id(weapon_id)
                    include = usage_slot is not None and status.weapon_usage_count_slot(usage_slot) != 0
            if include:
                used.append(weapon_id)
        used.sort()
        return used

    def _weapon_entry(self, weapon_id: int) -> Weapon:
        from ...weapons import WEAPON_BY_ID, WeaponId

        return WEAPON_BY_ID[WeaponId(weapon_id)]

    def _weapon_rpm(self, weapon: Weapon) -> int:
        return int(60.0 / float(weapon.shot_cooldown))

    def _draw_wicon(self, icon_index: int, *, pos: Vec2) -> None:
        tex = require_runtime_resources(self.state).texture(TextureId.UI_WICONS)
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
            rl.Rectangle(pos.x, pos.y, icon_w, icon_h),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )

    def _weapon_label_and_icon(self, weapon_id: int) -> tuple[str, int | None]:
        from ...weapons import WEAPON_BY_ID, WeaponId, weapon_display_name

        weapon = WEAPON_BY_ID[WeaponId(weapon_id)]
        name = weapon_display_name(weapon.weapon_id)
        return name, weapon.icon_index
