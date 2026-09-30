from __future__ import annotations

from crimson.game_states import GameStateId
from crimson.screens.actions import Route
from grim import canvas
from grim.color import grim_color
from grim.draw import grim_draw_rect_outline
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ...perks import PerkId
from ...ui.scrollbar import ui_scrollbar_draw, ui_scrollbar_update
from ...ui.text_wrap import perk_description_wrapped
from ..high_scores_layout import perks_db_right_detail_x_shift
from .databases_base import _DatabaseBaseView


class UnlockedPerksDatabaseView(_DatabaseBaseView):
    game_state = GameStateId.PERK_DATABASE

    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._perk_ids: list[PerkId] = []
        # Native `unlocked_perks_nav_focus_index`: Up/Down set it, and Enter at 0 goes back.
        self._nav_focus_index: int = 0

    def open(self) -> None:
        super().open()
        self._perk_ids = self._build_perk_database_ids()
        violence_disabled = self._violence_disabled()
        self.list_scroll.items = [self._perk_name(perk_id, violence_disabled=violence_disabled) for perk_id in self._perk_ids]
        self.list_scroll.hovered_index = -1

    def _back_button_pos(self) -> Vec2:
        # state_16: ui_buttonSm bbox [258,509]..[340,541] => relative to left panel (-98,194): (356, 315)
        return Vec2(356.0, 315.0)

    def _draw_contents(self, left_top_left: Vec2, right_top_left: Vec2, *, font: SmallFontData) -> None:
        left = left_top_left
        right = right_top_left
        text_color = rl.WHITE
        dim_color = rl.Color(255, 255, 255, int(255 * 0.7))
        violence_disabled = self._violence_disabled()
        detail_shift_x = perks_db_right_detail_x_shift(float(self.state.config.display.width))

        # state_16 title at (163,244) => relative to left panel (-98,194): (261,50)
        title_pos = left + Vec2(261.0, 50.0)
        title_text = "Unlocked Perks Database"
        draw_small_text(font, title_text, title_pos, rl.Color(255, 255, 255, 255))
        title_w = measure_small_text_width(font, title_text)
        # `draw_title_separator`: the title's underline at 0.5.
        grim_draw_rect_outline(title_pos.offset(dy=13.0), title_w, 1.0, grim_color(1.0, 1.0, 1.0, 0.5))

        perk_ids = self._perk_ids
        count = len(perk_ids)
        perk_label = "perk" if count == 1 else "perks"
        draw_small_text(font, f"{count} {perk_label} in database", left + Vec2(210.0, 78.0), dim_color)
        draw_small_text(font, "Perks", left + Vec2(210.0, 106.0), text_color)

        ui_scrollbar_draw(
            font, self.state.focus, self.list_scroll, left + Vec2(212.0, 126.0), mouse=Vec2.from_xy(canvas.mouse_position()),
        )

        perk_id = self._detail_perk_id()
        if perk_id is None:
            return
        perk_name = self._perk_name(perk_id, violence_disabled=violence_disabled)
        detail_anchor = right + Vec2(34.0 + detail_shift_x, 72.0)
        perk_no_label = "perkno"
        draw_small_text(
            font,
            f"{perk_no_label} #{perk_id}",
            detail_anchor + Vec2(190.0, -40.0),
            rl.Color(255, 255, 255, int(255 * 0.4)),
        )
        name_w = measure_small_text_width(font, perk_name)
        # Native centres the name on the int text width halved with C integer division.
        perk_name_pos = Vec2(detail_anchor.x + 128.0 - float(int(name_w) // 2), detail_anchor.y - 22.0)
        draw_small_text(font, perk_name, perk_name_pos, text_color)
        grim_draw_rect_outline(perk_name_pos.offset(dy=13.0), name_w, 1.0, grim_color(1.0, 1.0, 1.0, 0.5))

        desc_pos = detail_anchor + Vec2(16.0, 0.0)
        prereq_name = self._perk_prereq_name(perk_id, violence_disabled=violence_disabled)
        if prereq_name:
            draw_small_text(font, f"Requires: {prereq_name}", desc_pos, rl.Color(255, 204, 204, int(255 * 0.8)))
            desc_pos = desc_pos.offset(dy=18.0)

        wrapped_desc = perk_description_wrapped(font, perk_id, violence_disabled=violence_disabled)
        if wrapped_desc:
            draw_small_text(font, wrapped_desc, desc_pos, dim_color)

    def _update_content_interaction(self, *, left_top_left: Vec2, mouse: rl.Vector2) -> None:
        focus = self.state.focus
        if focus.up:
            self._nav_focus_index = 0
        if focus.down:
            self._nav_focus_index = 1

        ui_scrollbar_update(
            focus,
            self.list_scroll,
            left_top_left + Vec2(212.0, 126.0),
            mouse=Vec2.from_xy(mouse),
            click=rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT),
            down=rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT),
            wheel=rl.get_mouse_wheel_move(),
            cursor=True,
        )

        if self._nav_focus_index == 0 and focus.enter:
            self._begin_close_transition(Route.BACK)

    def _hovered_perk_id(self) -> PerkId | None:
        if self.list_scroll.hovered_index != -1:
            return self._perk_ids[self.list_scroll.hovered_index]
        return None

    def _selected_perk_id(self) -> PerkId | None:
        if 0 <= self.list_scroll.selected_index < len(self._perk_ids):
            return self._perk_ids[self.list_scroll.selected_index]
        return None

    def _detail_perk_id(self) -> PerkId | None:
        """The perk under the mouse, as native; the port also details the row the keys moved to."""
        hovered = self._hovered_perk_id()
        if hovered is not None or not self.list_scroll.keyed:
            return hovered
        return self._selected_perk_id()

    def _build_perk_database_ids(self) -> list[PerkId]:
        from ...perks.availability import build_perk_availability

        available = build_perk_availability(status=self.state.status)
        perk_ids = [PerkId(idx) for idx, available in enumerate(available) if available and idx > 0]
        perk_ids.sort()
        return perk_ids

    @staticmethod
    def _perk_name(perk_id: PerkId, *, violence_disabled: int = 0) -> str:
        from ...perks import perk_display_name

        return perk_display_name(
            perk_id,
            violence_disabled=int(violence_disabled),
        )

    @staticmethod
    def _perk_prereq_name(perk_id: PerkId, *, violence_disabled: int = 0) -> str | None:
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
        )

    def _violence_disabled(self) -> int:
        return self.state.config.display.violence_disabled

