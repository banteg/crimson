from __future__ import annotations

from collections.abc import Sequence

import msgspec

from crimson.game_states import GameStateId
from crimson.screens.ui_timeline import UiTimeline
from crimson.ui.animation import ui_element_anim, ui_elements_max_timeline
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData, measure_small_text_width
from grim.math import clamp
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...perks import PerkId, perk_display_description, perk_display_name
from ...sim.state_types import PerkCounts, PlayerState
from ...ui.focus import UiFocus
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import (
    PerkMenuLayout,
    UiButtonState,
    UiMenuItem,
    button_draw,
    button_update,
    draw_menu_item,
    draw_ui_text,
    menu_item_hit_rect,
    perk_menu_compute_layout,
    ui_menu_item_update,
)

UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))


class PerkMenuRuntime(msgspec.Struct, kw_only=True):
    standalone_timeline: UiTimeline = msgspec.field(default_factory=UiTimeline)
    standalone_focus: UiFocus = msgspec.field(default_factory=UiFocus)

    def ui_timeline(self) -> UiTimeline:
        """The menu timeline the perk selection state runs on."""
        return self.standalone_timeline

    def ui_focus(self) -> UiFocus:
        """The menu keyboard focus the choices and Cancel register with."""
        return self.standalone_focus

    def on_close(self) -> None:
        return None

    def play_sfx(self, sfx_id: SfxId) -> None:
        _ = sfx_id


class PerkMenuUiContext(msgspec.Struct, frozen=True):
    player: PlayerState
    perks: PerkCounts
    violence_disabled: int
    resources: RuntimeResources
    mouse: rl.Vector2
    shadows_enabled: bool = False


class PerkMenuController:
    _DESC_WRAP_WIDTH_PX = 256.0

    def __init__(
        self,
        *,
        cancel_label: str = "Cancel",
        runtime: PerkMenuRuntime | None = None,
    ) -> None:
        self._cancel_label = cancel_label
        self._runtime = runtime if runtime is not None else PerkMenuRuntime()
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
    def timeline(self) -> UiTimeline:
        return self._runtime.ui_timeline()

    @property
    def focus(self) -> UiFocus:
        return self._runtime.ui_focus()

    @property
    def active(self) -> bool:
        """Open, or still sliding out: gameplay resumes once the timeline drops below 0."""
        return self._open or self._closing

    def reset(self) -> None:
        self._layout = PerkMenuLayout()
        self._cancel_button = UiButtonState(self._cancel_label)
        # `perk_selection_screen_update`'s `choice_items`: one menu item per perk choice.
        self._choice_items = tuple(UiMenuItem() for _ in range(10))
        self._open = False
        self._closing = False
        self._selected_index = 0
        self._wrapped_desc_cache: dict[tuple[int, int], str] = {}

    def _prewrapped_perk_desc(
        self,
        perk_id: PerkId,
        font: SmallFontData,
        *,
        violence_disabled: int,
    ) -> str:
        key = (int(perk_id), int(violence_disabled))
        cached = self._wrapped_desc_cache.get(key)
        if cached is not None:
            return cached
        desc = perk_display_description(
            perk_id,
            violence_disabled=int(violence_disabled),
        )
        wrapped = self._wrap_small_text_native(
            font,
            desc,
            max_width_px=self._DESC_WRAP_WIDTH_PX,
        )
        self._wrapped_desc_cache[key] = wrapped
        return wrapped

    @staticmethod
    def _wrap_small_text_native(font: SmallFontData, text: str, max_width_px: float) -> str:
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

    def close(self) -> None:
        if not self._open:
            return
        self._open = False
        self._closing = True
        self.timeline.begin()
        self._runtime.on_close()

    def open_menu(self) -> None:
        """`game_state_set(GAME_STATE_PERK_SELECTION)`."""
        if self._open:
            return
        self._runtime.play_sfx(SfxId.UI_PANELCLICK)
        self._open = True
        self._selected_index = 0
        # The choices register first, so this focuses the first one (native keeps whatever index was focused).
        self.focus.index = 0
        self.timeline.enter(ui_elements_max_timeline(GameStateId.PERK_SELECTION))

    def tick_timeline(self) -> None:
        """Once the panel has slid out, the pending state is gameplay: `game_state_set(GAME_STATE_GAMEPLAY)`."""
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

        screen_w = float(canvas.width())
        slide_x = ui_element_anim(self.timeline.timeline_ms, index=27, width=self._layout.panel_size.x)[1]

        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        master_owned = PerkId.PERK_MASTER in ctx.perks
        expert_owned = PerkId.PERK_EXPERT in ctx.perks
        computed = perk_menu_compute_layout(
            self._layout,
            screen_w=screen_w,
            choice_count=len(choices),
            expert_owned=expert_owned,
            master_owned=master_owned,
            panel_slide_x=slide_x,
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
            self._runtime.play_sfx(SfxId.UI_BUTTONCLICK)
            self.close()
            return None

        # Native only takes a choice under the mouse; the port also takes the selected one on Enter, Space or A.
        if picked is None and (focus.enter or rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE)):
            picked = self._selected_index
        if picked is not None:
            self._runtime.play_sfx(SfxId.UI_BUTTONCLICK)
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

        screen_w = float(canvas.width())
        slide_x = ui_element_anim(self.timeline.timeline_ms, index=27, width=self._layout.panel_size.x)[1]

        master_owned = PerkId.PERK_MASTER in ctx.perks
        expert_owned = PerkId.PERK_EXPERT in ctx.perks
        computed = perk_menu_compute_layout(
            self._layout,
            screen_w=screen_w,
            choice_count=len(choices),
            expert_owned=expert_owned,
            master_owned=master_owned,
            panel_slide_x=slide_x,
        )

        panel_tex = ctx.resources.texture(TextureId.UI_MENU_PANEL)
        draw_classic_menu_panel(panel_tex, dst=computed.panel.to_rl(), shadow=bool(ctx.shadows_enabled))

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
        desc = self._prewrapped_perk_desc(
            selected,
            ctx.resources.small_font,
            violence_disabled=int(ctx.violence_disabled),
        )
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
