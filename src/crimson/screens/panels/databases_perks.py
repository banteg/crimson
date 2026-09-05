from __future__ import annotations

from crimson.screens.actions import Route
from grim.audio import play_sfx
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...game.types import GameState
from ...perks import PerkId
from ..high_scores_layout import perks_db_right_detail_x_shift
from .databases_base import _DatabaseBaseView


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
        self._perk_ids: list[PerkId] = []
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
        text_color = rl.WHITE
        dim_color = rl.Color(255, 255, 255, int(255 * 0.7))
        violence_disabled = self._violence_disabled()
        detail_shift_x = perks_db_right_detail_x_shift(float(self.state.config.display.width))

        # state_16 title at (163,244) => relative to left panel (-98,194): (261,50)
        title_pos = left + Vec2(261.0 * scale, 50.0 * scale)
        title_text = "Unlocked Perks Database"
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

        perk_ids = self._perk_ids
        count = len(perk_ids)
        perk_label = "perk" if count == 1 else "perks"
        draw_small_text(font, f"{count} {perk_label} in database", left + Vec2(210.0 * scale, 78.0 * scale), dim_color)
        draw_small_text(font, "Perks", left + Vec2(210.0 * scale, 106.0 * scale), text_color)

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
                self._perk_name(perk_id, violence_disabled=violence_disabled, preserve_bugs=preserve_bugs),
                list_top_left.offset(dy=float(row) * row_step),
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
        perk_id = hovered_perk_id
        perk_name = self._perk_name(perk_id, violence_disabled=violence_disabled, preserve_bugs=preserve_bugs)
        detail_anchor = right + Vec2((34.0 + detail_shift_x) * scale, 72.0 * scale)
        perk_no_label = "perkno"
        draw_small_text(
            font,
            f"{perk_no_label} #{perk_id}",
            detail_anchor + Vec2(190.0 * scale, -40.0 * scale),
            rl.Color(255, 255, 255, int(255 * 0.4)),
        )
        name_w = measure_small_text_width(font, perk_name)
        perk_name_pos = Vec2(detail_anchor.x + 128.0 * scale - name_w * 0.5, detail_anchor.y - 22.0 * scale)
        draw_small_text(font, perk_name, perk_name_pos, text_color)
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
        prereq_name = self._perk_prereq_name(perk_id, violence_disabled=violence_disabled, preserve_bugs=preserve_bugs)
        if prereq_name:
            draw_small_text(font, f"Requires: {prereq_name}", desc_pos, rl.Color(255, 204, 204, int(255 * 0.8)))
            desc_pos = desc_pos.offset(dy=18.0 * scale)

        wrapped_desc = self._prewrapped_perk_desc(perk_id, font, violence_disabled=violence_disabled)
        if wrapped_desc:
            draw_small_text(font, wrapped_desc, desc_pos, dim_color)

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
        mouse_in_list = (
            list_hit_x <= mouse.x < list_hit_x + list_hit_w and list_hit_y <= mouse.y < list_hit_y + list_hit_h
        )
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
            in_thumb = (
                thumb_x <= mouse.x < thumb_x + thumb_w and thumb_top <= mouse.y < thumb_top + thumb_h + 1.0 * scale
            )

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
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._begin_close_transition(Route.BACK)

    def _hovered_perk_id(self) -> PerkId | None:
        if 0 <= int(self._hovered_row_index) < len(self._perk_ids):
            return self._perk_ids[int(self._hovered_row_index)]
        return None

    def _selected_perk_id(self) -> PerkId | None:
        if 0 <= int(self._selected_row_index) < len(self._perk_ids):
            return self._perk_ids[int(self._selected_row_index)]
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

    def _build_perk_database_ids(self) -> list[PerkId]:
        from ...perks.availability import build_perk_availability

        available = build_perk_availability(status=self.state.status)
        perk_ids = [PerkId(idx) for idx, available in enumerate(available) if available and idx > 0]
        perk_ids.sort()
        return perk_ids

    @staticmethod
    def _perk_name(perk_id: PerkId, *, violence_disabled: int = 0, preserve_bugs: bool = False) -> str:
        from ...perks import perk_display_name

        return perk_display_name(
            perk_id,
            violence_disabled=int(violence_disabled),
            preserve_bugs=bool(preserve_bugs),
        )

    @staticmethod
    def _perk_desc(perk_id: PerkId, *, violence_disabled: int = 0, preserve_bugs: bool = False) -> str:
        from ...perks import perk_display_description

        return perk_display_description(
            perk_id,
            violence_disabled=int(violence_disabled),
            preserve_bugs=bool(preserve_bugs),
        )

    @staticmethod
    def _perk_prereq_name(perk_id: PerkId, *, violence_disabled: int = 0, preserve_bugs: bool = False) -> str | None:
        from ...perks import PERK_BY_ID, perk_display_name

        meta = PERK_BY_ID.get(perk_id)
        if meta is None:
            return None
        prereq = meta.prereq
        if not prereq:
            return None
        return perk_display_name(
            prereq[0],
            violence_disabled=int(violence_disabled),
            preserve_bugs=bool(preserve_bugs),
        )

    def _preserve_bugs(self) -> bool:
        return self.state.preserve_bugs

    def _violence_disabled(self) -> int:
        return self.state.config.display.violence_disabled

    def _prewrapped_perk_desc(self, perk_id: PerkId, font: SmallFontData, *, violence_disabled: int) -> str:
        key = (int(perk_id), int(violence_disabled), int(bool(self._preserve_bugs())))
        cached = self._wrapped_desc_cache.get(key)
        if cached is not None:
            return cached
        desc = self._perk_desc(perk_id, violence_disabled=violence_disabled, preserve_bugs=self._preserve_bugs())
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

            remaining -= measure_small_text_width(font, ch)
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
