from __future__ import annotations

from collections.abc import Callable, Sequence

import msgspec

from crimson.game_states import GameStateId
from crimson.screens.ui_timeline import UiTimeline
from crimson.ui.animation import ui_element_timeline_window, ui_elements_max_timeline
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.math import clamp
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...perks import PerkId, perk_display_name
from ...sim.state_types import PerkCounts, PlayerState
from ...ui.button import UiButtonState, button_draw, button_update
from ...ui.focus import UiFocus
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ...ui.perk_menu import (
    UiMenuItem,
    draw_menu_item,
    draw_ui_text,
    menu_item_hit_rect,
    perk_menu_compute_layout,
    ui_menu_item_update,
)
from ...ui.text_wrap import perk_description_wrapped

UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))


class PerkMenuUiContext(msgspec.Struct, frozen=True):
    player: PlayerState
    perks: PerkCounts
    violence_disabled: int
    resources: RuntimeResources
    mouse: rl.Vector2
    shadows_enabled: bool = False


class PerkMenuController:

    def __init__(
        self,
        *,
        timeline: UiTimeline,
        focus: UiFocus,
        play_sfx: Callable[[SfxId], None],
        cancel_label: str = "Cancel",
    ) -> None:
        # The menu timeline perk selection runs on and the keyboard focus its choices register with; the game
        # shares both across screens and rebinds them here.
        self.timeline = timeline
        self.focus = focus
        self._play_sfx = play_sfx
        self._cancel_label = cancel_label
        self.reset()

    @property
    def open(self) -> bool:
        return bool(self._open)

    @open.setter
    def open(self, value: bool) -> None:
        if not value and self._open:
            self.close()
        else:
            self._open = bool(value)

    @property
    def selected_index(self) -> int:
        return int(self._selected_index)

    @selected_index.setter
    def selected_index(self, value: int) -> None:
        self._selected_index = int(value)

    @property
    def active(self) -> bool:
        """Open, or still sliding out: gameplay resumes once the timeline drops below 0."""
        return self._open or self._closing

    def reset(self) -> None:
        self._cancel_button = UiButtonState(self._cancel_label)
        # `perk_selection_screen_update`'s `choice_items`: one menu item per perk choice.
        self._choice_items = tuple(UiMenuItem() for _ in range(10))
        self._open = False
        self._closing = False
        self._panel_clicked = False
        self._selected_index = 0

    def close(self) -> None:
        if not self._open:
            return
        self._open = False
        self._closing = True
        self.timeline.begin()

    def open_menu(self) -> None:
        """`game_state_set(GAME_STATE_PERK_SELECTION)`."""
        if self._open:
            return
        self._open = True
        self._panel_clicked = False
        self._selected_index = 0
        # The choices register first, so this focuses the first one (native keeps whatever index was focused).
        self.focus.index = 0
        self.timeline.enter(ui_elements_max_timeline(GameStateId.PERK_SELECTION))

    def tick_timeline(self) -> None:
        """`ui_element_update` clicks as the panel (slot 27) comes in; once it has slid out, the pending state is
        gameplay: `game_state_set(GAME_STATE_GAMEPLAY)`."""
        if self._open and not self._panel_clicked and self.timeline.timeline_ms >= ui_element_timeline_window(27)[1]:
            self._play_sfx(SfxId.UI_PANELCLICK)
            self._panel_clicked = True
        if self._closing and self.timeline.ready:
            self._closing = False
            self.timeline.enter(ui_elements_max_timeline(GameStateId.GAMEPLAY))

    def handle_input(
        self,
        ctx: PerkMenuUiContext,
        choices: Sequence[PerkId],
        *,
        dt_ui_ms: float,
    ) -> int | None:
        if not choices:
            self.close()
            return None

        if self._selected_index >= len(choices):
            self._selected_index = 0
        focus = self.focus

        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        master_owned = PerkId.PERK_MASTER in ctx.perks
        expert_owned = PerkId.PERK_EXPERT in ctx.perks
        computed = perk_menu_compute_layout(
            ui_panel_rect(27, self.timeline.timeline_ms, canvas.width()),
            choice_count=len(choices),
            expert_owned=expert_owned,
            master_owned=master_owned,
        )

        # `perk_selection_screen_update`: the choices are menu items, then Cancel is a button, in focus order. The
        # hovered choice is the selected one; the port also selects the focused one, so Tab and the pad walk them.
        items = self._choice_items[: len(choices)]
        picked: int | None = None
        for idx, perk_id in enumerate(choices):
            item = items[idx]
            item.label = perk_display_name(
                perk_id,
                violence_disabled=int(ctx.violence_disabled),
            )
            item_pos = computed.list_pos.offset(dy=float(idx) * computed.list_step_y)
            rect = menu_item_hit_rect(ctx.resources, item.label, pos=item_pos)
            if ui_menu_item_update(item, focus=focus, hit=rect, mouse=ctx.mouse, click=click) and picked is None:
                picked = idx
            if item.hovered or item.focused:
                self._selected_index = idx

        # The port's arrow keys step the selection and move the focus with it; native has no arrow keys here.
        step = int(focus.down) - int(focus.up)
        if step:
            self._selected_index = (self._selected_index + step) % len(choices)
            focus.set(items[self._selected_index], reset_timer=True)

        if button_update(
            ctx.resources,
            self._cancel_button,
            focus=focus,
            pos=computed.cancel_pos,
            dt_ms=float(dt_ui_ms),
            mouse=ctx.mouse,
            click=click,
        ):
            self._play_sfx(SfxId.UI_BUTTONCLICK)
            self.close()
            return None

        # Native only takes a choice under the mouse; the port also takes the selected one on Enter, Space or A.
        if picked is None and (focus.enter or rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE)):
            picked = self._selected_index
        if picked is not None:
            self._play_sfx(SfxId.UI_BUTTONCLICK)
            self.close()
            return int(picked)
        return None

    def draw(self, ctx: PerkMenuUiContext, choices: Sequence[PerkId]) -> None:
        menu_t = clamp(self.timeline.timeline_ms / ui_elements_max_timeline(GameStateId.PERK_SELECTION), 0.0, 1.0)
        if menu_t <= 1e-3:
            return

        if not choices:
            return
        if self._selected_index >= len(choices):
            self._selected_index = 0

        master_owned = PerkId.PERK_MASTER in ctx.perks
        expert_owned = PerkId.PERK_EXPERT in ctx.perks
        computed = perk_menu_compute_layout(
            ui_panel_rect(27, self.timeline.timeline_ms, canvas.width()),
            choice_count=len(choices),
            expert_owned=expert_owned,
            master_owned=master_owned,
        )

        draw_ui_panel(ctx.resources, 27, computed.panel, shadow=bool(ctx.shadows_enabled))

        title_tex = ctx.resources.texture(TextureId.UI_TEXT_PICK_A_PERK)
        src = rl.Rectangle(0.0, 0.0, float(title_tex.width), float(title_tex.height))
        rl.draw_texture_pro(
            title_tex,
            src,
            computed.title.to_rl(),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )

        sponsor = None
        if master_owned:
            sponsor = "extra perks sponsored by the Perk Master"
        elif expert_owned:
            sponsor = "extra perk sponsored by the Perk Expert"
        if sponsor:
            draw_ui_text(ctx.resources, sponsor, computed.sponsor_pos, color=UI_SPONSOR_COLOR)

        for idx, perk_id in enumerate(choices):
            label = perk_display_name(
                perk_id,
                violence_disabled=int(ctx.violence_disabled),
            )
            item_pos = computed.list_pos.offset(dy=float(idx) * computed.list_step_y)
            rect = menu_item_hit_rect(ctx.resources, label, pos=item_pos)
            hovered = rect.contains(ctx.mouse) or (idx == self._selected_index)
            if self._choice_items[idx].focused:
                self.focus.draw(item_pos.offset(dx=-16.0))
            draw_menu_item(ctx.resources, label, pos=item_pos, hovered=hovered)

        selected = choices[self._selected_index]
        desc = perk_description_wrapped(ctx.resources.small_font, selected, violence_disabled=int(ctx.violence_disabled))
        draw_ui_text(
            ctx.resources,
            desc,
            computed.desc.top_left,
            color=UI_TEXT_COLOR,
        )

        button_draw(
            ctx.resources,
            self._cancel_button,
            focus=self.focus,
            pos=computed.cancel_pos,
        )
