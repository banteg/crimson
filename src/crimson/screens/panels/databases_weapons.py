from __future__ import annotations

from typing import TYPE_CHECKING

from grim.assets import TextureId
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ..assets import require_runtime_resources
from ..high_scores_layout import weapons_db_right_detail_x_shift
from .databases_base import _DatabaseBaseView

if TYPE_CHECKING:
    from ...weapons import Weapon


class UnlockedWeaponsDatabaseView(_DatabaseBaseView):
    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._weapon_ids: list[int] = []
        self._selected_weapon_id: int | None = None
        self._list_scroll_index: int = 0

    def open(self) -> None:
        super().open()
        self._weapon_ids = self._build_weapon_database_ids()
        self._selected_weapon_id = None
        self._list_scroll_index = 0

    def close(self) -> None:
        self._selected_weapon_id = None
        super().close()

    def _back_button_pos(self) -> Vec2:
        # state_15: ui_buttonSm bbox [270,507]..[352,539] => relative to left panel (-98,194): (368, 313)
        return Vec2(368.0, 313.0)

    def _draw_contents(self, left_top_left: Vec2, right_top_left: Vec2, *, scale: float, font: SmallFontData) -> None:
        left = left_top_left
        right = right_top_left
        detail_shift_x = weapons_db_right_detail_x_shift(float(self.state.config.display.width))
        detail_top_left = right + Vec2(detail_shift_x * scale, 0.0)
        dim_color = rl.Color(255, 255, 255, int(255 * 0.7))
        text_color = rl.WHITE

        # state_15 title at (153,244) => relative to left panel (-98,194): (251,50)
        title_pos = left + Vec2(251.0 * scale, 50.0 * scale)
        title_text = "Unlocked Weapons Database"
        draw_small_text(font, title_text, title_pos, rl.Color(255, 255, 255, 255))
        title_w = measure_small_text_width(font, title_text)
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
        draw_small_text(font, f"{count} {weapon_label} in database", left + Vec2(210.0 * scale, 80.0 * scale), dim_color)
        draw_small_text(font, "Weapon", left + Vec2(210.0 * scale, 108.0 * scale), text_color)

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
            draw_small_text(font, name, list_top_left.offset(dy=float(row) * row_step), row_color)

        if self._selected_weapon_id is None:
            return

        weapon_id = int(self._selected_weapon_id)
        name, icon_index = self._weapon_label_and_icon(weapon_id)
        weapon = self._weapon_entry(weapon_id)
        weapon_no_label = "wepno"
        draw_small_text(font, f"{weapon_no_label} #{weapon_id}", detail_top_left + Vec2(240.0 * scale, 32.0 * scale), rl.Color(255, 255, 255, int(255 * 0.4)))
        draw_small_text(font, name, detail_top_left + Vec2(50.0 * scale, 50.0 * scale), text_color)
        if icon_index is not None:
            self._draw_wicon(icon_index, pos=detail_top_left + Vec2(82.0 * scale, 82.0 * scale), scale=scale)

        reload_time = weapon.reload_time
        clip_size = weapon.clip_size
        ammo_class = int(weapon.ammo_class or 0)
        firerate_label = "Firerate"
        if ammo_class == 1:
            firerate_text = f"{firerate_label}: n/a"
        else:
            firerate_text = f"{firerate_label}: {self._weapon_rpm(weapon)} rpm"
        draw_small_text(font, firerate_text, detail_top_left + Vec2(66.0 * scale, 128.0 * scale), text_color)
        draw_small_text(font, f"Reload time: {reload_time:.1f} secs", detail_top_left + Vec2(66.0 * scale, 146.0 * scale), text_color)
        draw_small_text(font, f"Clip size: {clip_size}", detail_top_left + Vec2(66.0 * scale, 164.0 * scale), text_color)

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
                    include = bool(
                        status is not None
                        and usage_slot is not None
                        and status.weapon_usage_count_slot(usage_slot) != 0,
                    )
            if include:
                used.append(weapon_id)
        used.sort()
        return used

    def _weapon_entry(self, weapon_id: int) -> Weapon:
        from ...weapons import WEAPON_BY_ID, WeaponId

        return WEAPON_BY_ID[WeaponId(weapon_id)]

    def _weapon_rpm(self, weapon: Weapon) -> int:
        return int(60.0 / float(weapon.shot_cooldown))

    def _draw_wicon(self, icon_index: int, *, pos: Vec2, scale: float) -> None:
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
            rl.Rectangle(pos.x, pos.y, icon_w * scale, icon_h * scale),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )

    def _weapon_label_and_icon(self, weapon_id: int) -> tuple[str, int | None]:
        from ...weapons import WEAPON_BY_ID, WeaponId, weapon_display_name

        weapon = WEAPON_BY_ID[WeaponId(weapon_id)]
        name = weapon_display_name(weapon.weapon_id, preserve_bugs=self.state.preserve_bugs)
        return name, weapon.icon_index
