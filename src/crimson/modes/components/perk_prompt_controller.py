from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from grim.config import CrimsonConfig
from grim.math import clamp

from ...input_codes import (
    input_code_is_down_for_player,
    input_code_is_pressed_for_player,
    input_primary_just_pressed,
    player_fire_keybind,
)
from .perk_menu_controller import PerkMenuUiContext
from .perk_prompt_ui import PERK_PROMPT_MAX_TIMER_MS, PerkPromptUi

UiTextWidthFn = Callable[[str, float], int]


@dataclass(slots=True)
class PerkPromptState:
    pending_count: int = 0
    timer_ms: float = 0.0
    hover: bool = False
    pulse: float = 0.0

    def reset(self) -> None:
        self.pending_count = 0
        self.timer_ms = 0.0
        self.hover = False
        self.pulse = 0.0

    def reset_if_pending(self, *, pending_count: int) -> None:
        if int(pending_count) > 0:
            self.reset()

    def begin_frame(self, *, pending_count: int) -> None:
        self.pending_count = int(pending_count)
        self.hover = False

    def poll_open_request(
        self,
        *,
        ctx: PerkMenuUiContext,
        config: CrimsonConfig,
        pending_count: int,
        player_count: int,
        any_alive: bool,
        paused: bool,
        menu_active: bool,
        prompt_scale: float = 1.0,
    ) -> bool:
        self.pending_count = int(pending_count)
        if int(pending_count) <= 0 or (not any_alive) or paused or menu_active:
            return False
        label = PerkPromptUi.label(config, pending_count=int(pending_count))
        if label:
            rect = PerkPromptUi.rect(resources=ctx.resources, scale=prompt_scale)
            self.hover = rect.contains(ctx.mouse)
        if self._prompt_open_requested(config=config, player_count=int(player_count)):
            self.pulse = 1000.0
            return True
        return False

    def tick_timer(
        self,
        *,
        pending_count: int,
        any_alive: bool,
        paused: bool,
        menu_active: bool,
        dt_ui_ms: float,
    ) -> None:
        self.pending_count = int(pending_count)
        prompt_visible = int(pending_count) > 0 and bool(any_alive) and (not paused) and (not menu_active)
        timer_delta = float(dt_ui_ms) if prompt_visible else -float(dt_ui_ms)
        self.timer_ms = clamp(self.timer_ms + timer_delta, 0.0, PERK_PROMPT_MAX_TIMER_MS)

    def tick_pulse(self, dt_ui_ms: float) -> None:
        pulse_delta = float(dt_ui_ms) * (6.0 if self.hover else -2.0)
        self.pulse = clamp(self.pulse + pulse_delta, 0.0, 1000.0)

    def draw(
        self,
        *,
        ctx: PerkMenuUiContext,
        pending_count: int,
        any_alive: bool,
        menu_active: bool,
        config: CrimsonConfig,
        ui_text_width: UiTextWidthFn,
        text_color,
        prompt_scale: float = 1.0,
    ) -> None:
        if menu_active or (not any_alive):
            return
        if int(pending_count) <= 0:
            return
        label = PerkPromptUi.label(config, pending_count=int(pending_count))
        if not label:
            return
        PerkPromptUi.draw(
            resources=ctx.resources,
            label=label,
            timer_ms=float(self.timer_ms),
            pulse=float(self.pulse),
            ui_text_width=ui_text_width,
            text_color=text_color,
            scale=float(prompt_scale),
        )

    def _prompt_open_requested(self, *, config: CrimsonConfig, player_count: int) -> bool:
        fire_key = player_fire_keybind(config, player_index=0)
        pick_key = config.keybind_pick_perk
        if input_code_is_pressed_for_player(pick_key, player_index=0) and (
            not input_code_is_down_for_player(fire_key, player_index=0)
        ):
            return True
        return self.hover and input_primary_just_pressed(config, player_count=player_count)
