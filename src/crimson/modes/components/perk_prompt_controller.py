from __future__ import annotations

from collections.abc import Callable

from grim.assets import RuntimeResources
from grim.config import CrimsonConfig
from grim.fonts.small import SmallFontData
from grim.math import clamp
from grim.raylib_api import rl

from ...input_codes import (
    config_keybinds_for_player,
    input_code_is_down_for_player,
    input_code_is_pressed_for_player,
    input_primary_just_pressed,
)
from .perk_menu_controller import PerkMenuContext, PerkMenuController
from .perk_prompt_ui import PERK_PROMPT_MAX_TIMER_MS, PerkPromptUi

PendingCountFn = Callable[[], int]
OnPromptOpenFn = Callable[[], None]
UiTextWidthFn = Callable[[str, float], int]


class PerkPromptController:
    def __init__(self, *, pending_count: PendingCountFn) -> None:
        self._pending_count = pending_count
        self.reset()

    def reset(self) -> None:
        self._timer_ms = 0.0
        self._hover = False
        self._pulse = 0.0

    def reset_on_close(self) -> None:
        if int(self._pending_count()) > 0:
            self.reset()

    def update(
        self,
        *,
        menu: PerkMenuController,
        ctx: PerkMenuContext,
        config: CrimsonConfig,
        dt: float,
        dt_ui_ms: float,
        any_alive: bool,
        paused: bool,
        allow_input: bool = True,
        allow_pulse: bool = True,
        scale: float = 1.0,
        on_open_attempt: OnPromptOpenFn | None = None,
        on_open_success: OnPromptOpenFn | None = None,
    ) -> None:
        pending_count = int(self._pending_count())
        prompt_pending = pending_count > 0 and bool(any_alive)

        self._hover = False
        if menu.open and allow_input:
            menu.handle_input(ctx, dt=float(dt), dt_ui_ms=float(dt_ui_ms))

        menu_active = menu.active
        if allow_input and (not menu_active) and prompt_pending and (not paused):
            label = PerkPromptUi.label(config, pending_count=pending_count)
            if label:
                rect = PerkPromptUi.rect(resources=ctx.resources, scale=scale)
                self._hover = rect.contains(ctx.mouse)
            if self._prompt_open_requested(config=config, player_count=int(ctx.player_count)):
                self._pulse = 1000.0
                if on_open_attempt is not None:
                    on_open_attempt()
                opened = menu.open_if_available(ctx)
                if opened and on_open_success is not None:
                    on_open_success()

        menu_active = menu.active
        if allow_pulse:
            pulse_delta = float(dt_ui_ms) * (6.0 if self._hover else -2.0)
            self._pulse = clamp(self._pulse + pulse_delta, 0.0, 1000.0)

        if prompt_pending and (not menu_active) and (not paused):
            delta = float(dt_ui_ms)
        else:
            delta = -float(dt_ui_ms)
        self._timer_ms = clamp(self._timer_ms + delta, 0.0, PERK_PROMPT_MAX_TIMER_MS)

        menu.tick_timeline(float(dt_ui_ms))

    def draw(
        self,
        *,
        menu: PerkMenuController,
        any_alive: bool,
        config: CrimsonConfig,
        font: SmallFontData | None,
        resources: RuntimeResources,
        ui_text_width: UiTextWidthFn,
        text_color: rl.Color,
        scale: float = 1.0,
        hidden: bool = False,
    ) -> None:
        if hidden or menu.active or (not any_alive):
            return
        pending_count = int(self._pending_count())
        if pending_count <= 0:
            return
        label = PerkPromptUi.label(config, pending_count=pending_count)
        if not label:
            return
        assert font is not None, "perk prompt requires small font after mode open"
        PerkPromptUi.draw(
            font=font,
            resources=resources,
            label=label,
            timer_ms=float(self._timer_ms),
            pulse=float(self._pulse),
            ui_text_width=ui_text_width,
            text_color=text_color,
            scale=scale,
        )

    def _prompt_open_requested(self, *, config: CrimsonConfig, player_count: int) -> bool:
        player0_binds = config_keybinds_for_player(config, player_index=0)
        fire_key = 0x100
        if len(player0_binds) >= 5:
            fire_key = int(player0_binds[4])

        pick_key = config.keybind_pick_perk
        if input_code_is_pressed_for_player(pick_key, player_index=0) and (
            not input_code_is_down_for_player(fire_key, player_index=0)
        ):
            return True
        return self._hover and input_primary_just_pressed(config, player_count=player_count)
