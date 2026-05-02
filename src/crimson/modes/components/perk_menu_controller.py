from __future__ import annotations

from collections.abc import Sequence

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData, measure_small_text_width
from grim.math import clamp
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...perks import PerkId, perk_display_description, perk_display_name
from ...sim.state_types import PlayerState
from ...ui.layout import ui_origin, ui_scale
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import (
    PERK_MENU_TRANSITION_MS,
    PerkMenuLayout,
    UiButtonState,
    button_draw,
    button_update,
    button_width,
    draw_menu_item,
    draw_ui_text,
    menu_item_hit_rect,
    perk_menu_compute_layout,
    perk_menu_panel_slide_x,
)

UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))


class PerkMenuRuntime(msgspec.Struct):
    def on_close(self) -> None:
        return None

    def play_sfx(self, sfx_id: SfxId) -> None:
        _ = sfx_id
        return None


class PerkMenuUiContext(msgspec.Struct, frozen=True):
    player: PlayerState
    violence_disabled: int
    preserve_bugs: bool
    resources: RuntimeResources
    mouse: rl.Vector2
    fx_detail: bool = False


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
    def timeline_ms(self) -> float:
        return float(self._timeline_ms)

    @timeline_ms.setter
    def timeline_ms(self, value: float) -> None:
        self._timeline_ms = float(value)

    @property
    def active(self) -> bool:
        return bool(self._open) or self._timeline_ms > 1e-3

    def reset(self) -> None:
        self._layout = PerkMenuLayout()
        self._cancel_button = UiButtonState(self._cancel_label)
        self._open = False
        self._selected_index = 0
        self._timeline_ms = 0.0
        self._wrapped_desc_cache: dict[tuple[int, int, int], str] = {}

    def _prewrapped_perk_desc(
        self,
        perk_id: PerkId,
        font: SmallFontData,
        *,
        violence_disabled: int,
        preserve_bugs: bool,
    ) -> str:
        key = (int(perk_id), int(violence_disabled), int(bool(preserve_bugs)))
        cached = self._wrapped_desc_cache.get(key)
        if cached is not None:
            return cached
        desc = perk_display_description(
            perk_id,
            violence_disabled=int(violence_disabled),
            preserve_bugs=bool(preserve_bugs),
        )
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

    def close(self) -> None:
        if not self._open:
            return
        self._open = False
        self._runtime.on_close()

    def open_menu(self) -> None:
        if self._open:
            return
        self._runtime.play_sfx(SfxId.UI_PANELCLICK)
        self._open = True
        self._selected_index = 0

    def tick_timeline(self, dt_ui_ms: float) -> None:
        if self._open:
            self._timeline_ms = clamp(self._timeline_ms + float(dt_ui_ms), 0.0, PERK_MENU_TRANSITION_MS)
        else:
            self._timeline_ms = clamp(self._timeline_ms - float(dt_ui_ms), 0.0, PERK_MENU_TRANSITION_MS)

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

        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._selected_index = (self._selected_index + 1) % len(choices)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._selected_index = (self._selected_index - 1) % len(choices)

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin = ui_origin(screen_w, screen_h, scale)
        slide_x = perk_menu_panel_slide_x(self._timeline_ms, width=self._layout.panel_size.x)

        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        master_owned = int(ctx.player.perk_counts[int(PerkId.PERK_MASTER)]) > 0
        expert_owned = int(ctx.player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        computed = perk_menu_compute_layout(
            self._layout,
            screen_w=screen_w,
            origin=origin,
            scale=scale,
            choice_count=len(choices),
            expert_owned=expert_owned,
            master_owned=master_owned,
            panel_slide_x=slide_x,
        )

        preserve_bugs = bool(ctx.preserve_bugs)
        for idx, perk_id in enumerate(choices):
            label = perk_display_name(
                perk_id,
                violence_disabled=int(ctx.violence_disabled),
                preserve_bugs=preserve_bugs,
            )
            item_pos = computed.list_pos.offset(dy=float(idx) * computed.list_step_y)
            rect = menu_item_hit_rect(ctx.resources, label, pos=item_pos, scale=scale)
            if rect.contains(ctx.mouse):
                self._selected_index = idx
                if click:
                    self._runtime.play_sfx(SfxId.UI_BUTTONCLICK)
                    self.close()
                    return int(idx)
                break

        cancel_w = button_width(
            ctx.resources,
            self._cancel_button.label,
            scale=scale,
            force_wide=self._cancel_button.force_wide,
        )
        if button_update(
            self._cancel_button,
            pos=computed.cancel_pos,
            width=cancel_w,
            dt_ms=float(dt_ui_ms),
            mouse=ctx.mouse,
            click=click,
        ):
            self._runtime.play_sfx(SfxId.UI_BUTTONCLICK)
            self.close()
            return None

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._runtime.play_sfx(SfxId.UI_BUTTONCLICK)
            self.close()
            return int(self._selected_index)
        return None

    def draw(self, ctx: PerkMenuUiContext, choices: Sequence[PerkId]) -> None:
        menu_t = clamp(self._timeline_ms / PERK_MENU_TRANSITION_MS, 0.0, 1.0)
        if menu_t <= 1e-3:
            return

        if not choices:
            return
        if self._selected_index >= len(choices):
            self._selected_index = 0

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin = ui_origin(screen_w, screen_h, scale)
        slide_x = perk_menu_panel_slide_x(self._timeline_ms, width=self._layout.panel_size.x)

        master_owned = int(ctx.player.perk_counts[int(PerkId.PERK_MASTER)]) > 0
        expert_owned = int(ctx.player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        computed = perk_menu_compute_layout(
            self._layout,
            screen_w=screen_w,
            origin=origin,
            scale=scale,
            choice_count=len(choices),
            expert_owned=expert_owned,
            master_owned=master_owned,
            panel_slide_x=slide_x,
        )

        panel_tex = ctx.resources.texture(TextureId.UI_MENU_PANEL)
        draw_classic_menu_panel(panel_tex, dst=computed.panel.to_rl(), shadow=bool(ctx.fx_detail))

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
            draw_ui_text(ctx.resources, sponsor, computed.sponsor_pos, scale=scale, color=UI_SPONSOR_COLOR)

        preserve_bugs = bool(ctx.preserve_bugs)
        for idx, perk_id in enumerate(choices):
            label = perk_display_name(
                perk_id,
                violence_disabled=int(ctx.violence_disabled),
                preserve_bugs=preserve_bugs,
            )
            item_pos = computed.list_pos.offset(dy=float(idx) * computed.list_step_y)
            rect = menu_item_hit_rect(ctx.resources, label, pos=item_pos, scale=scale)
            hovered = rect.contains(ctx.mouse) or (idx == self._selected_index)
            draw_menu_item(ctx.resources, label, pos=item_pos, scale=scale, hovered=hovered)

        selected = choices[self._selected_index]
        desc = perk_display_description(
            selected,
            violence_disabled=int(ctx.violence_disabled),
            preserve_bugs=preserve_bugs,
        )
        desc = self._prewrapped_perk_desc(
            selected,
            ctx.resources.small_font,
            violence_disabled=int(ctx.violence_disabled),
            preserve_bugs=preserve_bugs,
        )
        draw_ui_text(
            ctx.resources,
            desc,
            computed.desc.top_left,
            scale=scale,
            color=UI_TEXT_COLOR,
        )

        cancel_w = button_width(
            ctx.resources, self._cancel_button.label, scale=scale, force_wide=self._cancel_button.force_wide,
        )
        button_draw(
            ctx.resources,
            self._cancel_button,
            pos=computed.cancel_pos,
            width=cancel_w,
            scale=scale,
        )
