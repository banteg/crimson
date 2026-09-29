from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from grim.config import CrimsonConfig
from grim.math import clamp
from grim.raylib_api import rl

from ...input_codes import input_code_is_down, input_primary_just_pressed
from .perk_menu_controller import PerkMenuUiContext
from .perk_prompt_ui import PERK_PROMPT_MAX_TIMER_MS, PerkPromptUi

UiTextWidthFn = Callable[[str], int]


@dataclass(slots=True)
class PerkPromptState:
    """Native `perk_prompt_timer`, `perk_prompt_hover_active`, `perk_prompt_pulse` and `mouse_button_down`."""

    timer_ms: float = 0.0
    hover: bool = False
    pulse: float = 0.0
    mouse_down: bool = False

    def reset(self) -> None:
        self.timer_ms = 0.0
        self.hover = False
        self.pulse = 0.0
        self.mouse_down = False

    def tick_pulse(self, dt_ui_ms: float) -> None:
        """The sign glows up while hovered and fades otherwise; native runs this before the open check."""
        pulse_delta = float(dt_ui_ms) * (6.0 if self.hover else -2.0)
        self.pulse = clamp(self.pulse + pulse_delta, 0.0, 1000.0)

    def poll_open_request(
        self,
        *,
        ctx: PerkMenuUiContext,
        config: CrimsonConfig,
        pending_count: int,
        alive: bool,
        paused: bool,
        menu_active: bool,
        player_count: int,
    ) -> bool:
        """`gameplay_update_and_render`: the pick-perk key, Space, keypad + or a click on the sign opens the menu."""
        mouse_was_down = self.mouse_down
        self.mouse_down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        if paused or mouse_was_down or pending_count <= 0 or not alive or menu_active:
            return False
        if (
            input_code_is_down(config.controls.pick_perk_code, player_index=0)
            or rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE)
            or rl.is_key_pressed(rl.KeyboardKey.KEY_KP_ADD)
        ):
            self.pulse = 1000.0
            return True
        self.hover = PerkPromptUi.rect(resources=ctx.resources).contains(ctx.mouse)
        fire_codes = tuple(int(config.controls.player(idx).fire_code) for idx in range(4))
        return self.hover and input_primary_just_pressed(fire_codes=fire_codes, player_count=player_count)

    def tick_timer(self, *, pending_count: int, menu_active: bool, dt_ui_ms: float) -> None:
        """`perk_prompt_update_and_render`: swing in while a perk is pending in gameplay, out otherwise."""
        timer_delta = float(dt_ui_ms) if pending_count > 0 and not menu_active else -float(dt_ui_ms)
        self.timer_ms = clamp(self.timer_ms + timer_delta, 0.0, PERK_PROMPT_MAX_TIMER_MS)

    def draw(self, *, ctx: PerkMenuUiContext, config: CrimsonConfig, ui_text_width: UiTextWidthFn) -> None:
        PerkPromptUi.draw(
            resources=ctx.resources,
            label=PerkPromptUi.label(config),
            timer_ms=float(self.timer_ms),
            pulse=float(self.pulse),
            ui_text_width=ui_text_width,
        )
