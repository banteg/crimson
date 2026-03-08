from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from grim.assets import RuntimeResources
from grim.config import CrimsonConfig
from grim.math import clamp
from grim.raylib_api import rl

from ...input_codes import (
    config_keybinds_for_player,
    input_code_is_down_for_player,
    input_code_is_pressed_for_player,
    input_primary_just_pressed,
)
from .perk_prompt_ui import PERK_PROMPT_MAX_TIMER_MS, PerkPromptUi

UiTextWidthFn = Callable[[str, float], int]


@dataclass(slots=True)
class PerkPromptState:
    timer_ms: float = 0.0
    hover: bool = False
    pulse: float = 0.0

    def reset(self) -> None:
        self.timer_ms = 0.0
        self.hover = False
        self.pulse = 0.0

    def reset_if_pending(self, *, pending_count: int) -> None:
        if int(pending_count) > 0:
            self.reset()

    def update(
        self,
        *,
        config: CrimsonConfig,
        resources: RuntimeResources,
        mouse: rl.Vector2,
        pending_count: int,
        player_count: int,
        any_alive: bool,
        menu_active: bool,
        paused: bool,
        dt_ui_ms: float,
        allow_input: bool = True,
        allow_pulse: bool = True,
        scale: float = 1.0,
    ) -> bool:
        prompt_pending = int(pending_count) > 0 and bool(any_alive)
        self.hover = False
        open_requested = False

        if allow_input and (not menu_active) and prompt_pending and (not paused):
            label = PerkPromptUi.label(config, pending_count=int(pending_count))
            if label:
                rect = PerkPromptUi.rect(resources=resources, scale=scale)
                self.hover = rect.contains(mouse)
            if self._prompt_open_requested(config=config, player_count=int(player_count)):
                self.pulse = 1000.0
                open_requested = True

        if allow_pulse:
            pulse_delta = float(dt_ui_ms) * (6.0 if self.hover else -2.0)
            self.pulse = clamp(self.pulse + pulse_delta, 0.0, 1000.0)

        if prompt_pending and (not menu_active) and (not paused):
            delta = float(dt_ui_ms)
        else:
            delta = -float(dt_ui_ms)
        self.timer_ms = clamp(self.timer_ms + delta, 0.0, PERK_PROMPT_MAX_TIMER_MS)
        return bool(open_requested)

    def draw(
        self,
        *,
        pending_count: int,
        menu_active: bool,
        any_alive: bool,
        config: CrimsonConfig,
        resources: RuntimeResources,
        ui_text_width: UiTextWidthFn,
        text_color: rl.Color,
        scale: float = 1.0,
        hidden: bool = False,
    ) -> None:
        if hidden or menu_active or (not any_alive):
            return
        if int(pending_count) <= 0:
            return
        label = PerkPromptUi.label(config, pending_count=int(pending_count))
        if not label:
            return
        PerkPromptUi.draw(
            resources=resources,
            label=label,
            timer_ms=float(self.timer_ms),
            pulse=float(self.pulse),
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
        return self.hover and input_primary_just_pressed(config, player_count=player_count)
