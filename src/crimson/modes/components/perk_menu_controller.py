from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

import pyray as rl

from grim.fonts.small import SmallFontData
from grim.math import clamp

from ...gameplay import GameplayState, PerkSelectionState, PlayerState, perk_selection_current_choices, perk_selection_pick
from ...perks import PerkId, perk_display_description, perk_display_name
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import (
    PERK_MENU_TRANSITION_MS,
    PerkMenuAssets,
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
    wrap_ui_text,
)
from ...ui.layout import ui_origin, ui_scale

PlaySfxFn = Callable[[str], None]
OnCloseFn = Callable[[], None]

UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))


@dataclass(frozen=True, slots=True)
class PerkMenuContext:
    state: GameplayState
    perk_state: PerkSelectionState
    players: Sequence[PlayerState]
    creatures: Sequence[object]
    player: PlayerState
    game_mode: int
    player_count: int
    fx_toggle: int

    font: SmallFontData | None
    assets: PerkMenuAssets | None
    mouse: rl.Vector2
    fx_detail: bool = False
    play_sfx: PlaySfxFn | None = None


class PerkMenuController:
    def __init__(self, *, cancel_label: str = "Cancel", on_close: OnCloseFn | None = None) -> None:
        self._cancel_label = cancel_label
        self._on_close = on_close
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

    def close(self) -> None:
        if not self._open:
            return
        self._open = False
        if self._on_close is not None:
            self._on_close()

    def open_if_available(self, ctx: PerkMenuContext) -> bool:
        if self._open:
            return True
        if ctx.assets is None:
            return False
        choices = perk_selection_current_choices(
            ctx.state,
            ctx.players,
            ctx.perk_state,
            game_mode=int(ctx.game_mode),
            player_count=int(ctx.player_count),
        )
        if not choices:
            self._open = False
            return False
        if ctx.play_sfx is not None:
            ctx.play_sfx("sfx_ui_panelclick")
        self._open = True
        self._selected_index = 0
        return True

    def tick_timeline(self, dt_ui_ms: float) -> None:
        if self._open:
            self._timeline_ms = clamp(self._timeline_ms + float(dt_ui_ms), 0.0, PERK_MENU_TRANSITION_MS)
        else:
            self._timeline_ms = clamp(self._timeline_ms - float(dt_ui_ms), 0.0, PERK_MENU_TRANSITION_MS)

    def handle_input(self, ctx: PerkMenuContext, *, dt_frame: float, dt_ui_ms: float) -> None:
        if ctx.assets is None:
            self.close()
            return

        choices = perk_selection_current_choices(
            ctx.state,
            ctx.players,
            ctx.perk_state,
            game_mode=int(ctx.game_mode),
            player_count=int(ctx.player_count),
        )
        if not choices:
            self.close()
            return

        if self._selected_index >= len(choices):
            self._selected_index = 0

        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._selected_index = (self._selected_index + 1) % len(choices)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._selected_index = (self._selected_index - 1) % len(choices)

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin_x, origin_y = ui_origin(screen_w, screen_h, scale)
        slide_x = perk_menu_panel_slide_x(self._timeline_ms, width=self._layout.panel_w)

        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        master_owned = int(ctx.player.perk_counts[int(PerkId.PERK_MASTER)]) > 0
        expert_owned = int(ctx.player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        computed = perk_menu_compute_layout(
            self._layout,
            screen_w=screen_w,
            origin_x=origin_x,
            origin_y=origin_y,
            scale=scale,
            choice_count=len(choices),
            expert_owned=expert_owned,
            master_owned=master_owned,
            panel_slide_x=slide_x,
        )

        for idx, perk_id in enumerate(choices):
            label = perk_display_name(int(perk_id), fx_toggle=int(ctx.fx_toggle))
            item_x = computed.list_x
            item_y = computed.list_y + float(idx) * computed.list_step_y
            rect = menu_item_hit_rect(ctx.font, label, x=item_x, y=item_y, scale=scale)
            if rl.check_collision_point_rec(ctx.mouse, rect):
                self._selected_index = idx
                if click:
                    if ctx.play_sfx is not None:
                        ctx.play_sfx("sfx_ui_buttonclick")
                    picked = perk_selection_pick(
                        ctx.state,
                        ctx.players,
                        ctx.perk_state,
                        idx,
                        game_mode=int(ctx.game_mode),
                        player_count=int(ctx.player_count),
                        dt=float(dt_frame),
                        creatures=ctx.creatures,
                    )
                    if picked is not None and ctx.play_sfx is not None:
                        ctx.play_sfx("sfx_ui_bonus")
                    self.close()
                    return
                break

        cancel_w = button_width(
            ctx.font,
            self._cancel_button.label,
            scale=scale,
            force_wide=self._cancel_button.force_wide,
        )
        cancel_x = computed.cancel_x
        cancel_y = computed.cancel_y
        if button_update(
            self._cancel_button,
            x=cancel_x,
            y=cancel_y,
            width=cancel_w,
            dt_ms=float(dt_ui_ms),
            mouse=ctx.mouse,
            click=click,
        ):
            if ctx.play_sfx is not None:
                ctx.play_sfx("sfx_ui_buttonclick")
            self.close()
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            if ctx.play_sfx is not None:
                ctx.play_sfx("sfx_ui_buttonclick")
            picked = perk_selection_pick(
                ctx.state,
                ctx.players,
                ctx.perk_state,
                self._selected_index,
                game_mode=int(ctx.game_mode),
                player_count=int(ctx.player_count),
                dt=float(dt_frame),
                creatures=ctx.creatures,
            )
            if picked is not None and ctx.play_sfx is not None:
                ctx.play_sfx("sfx_ui_bonus")
            self.close()

    def draw(self, ctx: PerkMenuContext) -> None:
        menu_t = clamp(self._timeline_ms / PERK_MENU_TRANSITION_MS, 0.0, 1.0)
        if menu_t <= 1e-3:
            return
        if ctx.assets is None:
            return

        choices = perk_selection_current_choices(
            ctx.state,
            ctx.players,
            ctx.perk_state,
            game_mode=int(ctx.game_mode),
            player_count=int(ctx.player_count),
        )
        if not choices:
            return

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin_x, origin_y = ui_origin(screen_w, screen_h, scale)
        slide_x = perk_menu_panel_slide_x(self._timeline_ms, width=self._layout.panel_w)

        master_owned = int(ctx.player.perk_counts[int(PerkId.PERK_MASTER)]) > 0
        expert_owned = int(ctx.player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        computed = perk_menu_compute_layout(
            self._layout,
            screen_w=screen_w,
            origin_x=origin_x,
            origin_y=origin_y,
            scale=scale,
            choice_count=len(choices),
            expert_owned=expert_owned,
            master_owned=master_owned,
            panel_slide_x=slide_x,
        )

        panel_tex = ctx.assets.menu_panel
        if panel_tex is not None:
            draw_classic_menu_panel(panel_tex, dst=computed.panel, shadow=bool(ctx.fx_detail))

        title_tex = ctx.assets.title_pick_perk
        if title_tex is not None:
            src = rl.Rectangle(0.0, 0.0, float(title_tex.width), float(title_tex.height))
            rl.draw_texture_pro(title_tex, src, computed.title, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        sponsor = None
        if master_owned:
            sponsor = "extra perks sponsored by the Perk Master"
        elif expert_owned:
            sponsor = "extra perk sponsored by the Perk Expert"
        if sponsor:
            draw_ui_text(ctx.font, sponsor, computed.sponsor_x, computed.sponsor_y, scale=scale, color=UI_SPONSOR_COLOR)

        for idx, perk_id in enumerate(choices):
            label = perk_display_name(int(perk_id), fx_toggle=int(ctx.fx_toggle))
            item_x = computed.list_x
            item_y = computed.list_y + float(idx) * computed.list_step_y
            rect = menu_item_hit_rect(ctx.font, label, x=item_x, y=item_y, scale=scale)
            hovered = rl.check_collision_point_rec(ctx.mouse, rect) or (idx == self._selected_index)
            draw_menu_item(ctx.font, label, x=item_x, y=item_y, scale=scale, hovered=hovered)

        selected = choices[self._selected_index]
        desc = perk_display_description(int(selected), fx_toggle=int(ctx.fx_toggle))
        desc_x = float(computed.desc.x)
        desc_y = float(computed.desc.y)
        desc_w = float(computed.desc.width)
        desc_h = float(computed.desc.height)
        desc_scale = scale * 0.85
        desc_lines = wrap_ui_text(ctx.font, desc, max_width=desc_w, scale=desc_scale)
        line_h = float(ctx.font.cell_size * desc_scale) if ctx.font is not None else float(20 * desc_scale)
        y = desc_y
        for line in desc_lines:
            if y + line_h > desc_y + desc_h:
                break
            draw_ui_text(ctx.font, line, desc_x, y, scale=desc_scale, color=UI_TEXT_COLOR)
            y += line_h

        cancel_w = button_width(ctx.font, self._cancel_button.label, scale=scale, force_wide=self._cancel_button.force_wide)
        button_draw(ctx.assets, ctx.font, self._cancel_button, x=computed.cancel_x, y=computed.cancel_y, width=cancel_w, scale=scale)
