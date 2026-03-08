from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from grim.config import CrimsonConfig
from grim.math import clamp

from ...input_codes import (
    input_code_is_down_for_player,
    input_code_is_pressed_for_player,
    input_primary_just_pressed,
    player_fire_keybind,
)
from ...perks import PerkId
from .perk_menu_controller import PerkMenuController, PerkMenuUiContext, PlaySfxFn
from .perk_prompt_ui import PERK_PROMPT_MAX_TIMER_MS, PerkPromptUi

UiTextWidthFn = Callable[[str, float], int]


@dataclass(slots=True)
class _PerkPromptState:
    pending_count: int = 0
    timer_ms: float = 0.0
    hover: bool = False
    pulse: float = 0.0

    def reset(self) -> None:
        self.pending_count = 0
        self.timer_ms = 0.0
        self.hover = False
        self.pulse = 0.0


class PerkUiState:
    def __init__(
        self,
        *,
        cancel_label: str = "Cancel",
    ) -> None:
        self._prompt = _PerkPromptState()
        self._menu = PerkMenuController(cancel_label=cancel_label, on_close=self._handle_menu_closed)
        self.reset()

    @property
    def menu_open(self) -> bool:
        return self._menu.open

    @property
    def menu_active(self) -> bool:
        return self._menu.active

    def reset(self) -> None:
        self._prompt.reset()
        self._menu.reset()

    def close_menu(self) -> None:
        self._menu.close()

    def open_menu(self, *, play_sfx: PlaySfxFn | None = None) -> None:
        self._menu.open_menu(play_sfx=play_sfx)

    def handle_menu_input(
        self,
        ctx: PerkMenuUiContext,
        choices: Sequence[PerkId],
        *,
        dt_ui_ms: float,
    ) -> int | None:
        return self._menu.handle_input(ctx, choices, dt_ui_ms=float(dt_ui_ms))

    def tick_menu(self, dt_ui_ms: float) -> None:
        self._menu.tick_timeline(float(dt_ui_ms))

    def begin_prompt_frame(self, *, pending_count: int) -> None:
        self._prompt.pending_count = int(pending_count)
        self._prompt.hover = False

    def poll_prompt_open_request(
        self,
        *,
        ctx: PerkMenuUiContext,
        config: CrimsonConfig,
        pending_count: int,
        player_count: int,
        any_alive: bool,
        paused: bool,
        prompt_scale: float = 1.0,
    ) -> bool:
        self._prompt.pending_count = int(pending_count)
        if int(pending_count) <= 0 or (not any_alive) or paused or self._menu.active:
            return False
        label = PerkPromptUi.label(config, pending_count=int(pending_count))
        if label:
            rect = PerkPromptUi.rect(resources=ctx.resources, scale=prompt_scale)
            self._prompt.hover = rect.contains(ctx.mouse)
        if self._prompt_open_requested(config=config, player_count=int(player_count)):
            self._prompt.pulse = 1000.0
            return True
        return False

    def tick_prompt_timer(
        self,
        *,
        pending_count: int,
        any_alive: bool,
        paused: bool,
        dt_ui_ms: float,
    ) -> None:
        self._prompt.pending_count = int(pending_count)
        prompt_visible = int(pending_count) > 0 and bool(any_alive) and (not paused) and (not self._menu.active)
        timer_delta = float(dt_ui_ms) if prompt_visible else -float(dt_ui_ms)
        self._prompt.timer_ms = clamp(
            self._prompt.timer_ms + timer_delta,
            0.0,
            PERK_PROMPT_MAX_TIMER_MS,
        )

    def tick_prompt_pulse(self, dt_ui_ms: float) -> None:
        pulse_delta = float(dt_ui_ms) * (6.0 if self._prompt.hover else -2.0)
        self._prompt.pulse = clamp(self._prompt.pulse + pulse_delta, 0.0, 1000.0)

    def draw_prompt(
        self,
        *,
        ctx: PerkMenuUiContext,
        pending_count: int,
        any_alive: bool,
        config: CrimsonConfig,
        ui_text_width: UiTextWidthFn,
        text_color,
        prompt_scale: float = 1.0,
    ) -> None:
        if self._menu.active or (not any_alive):
            return
        if int(pending_count) <= 0:
            return
        label = PerkPromptUi.label(config, pending_count=int(pending_count))
        if not label:
            return
        PerkPromptUi.draw(
            resources=ctx.resources,
            label=label,
            timer_ms=float(self._prompt.timer_ms),
            pulse=float(self._prompt.pulse),
            ui_text_width=ui_text_width,
            text_color=text_color,
            scale=float(prompt_scale),
        )

    def draw_menu(self, ctx: PerkMenuUiContext, choices: Sequence[PerkId]) -> None:
        self._menu.draw(ctx, choices)

    def _handle_menu_closed(self) -> None:
        if int(self._prompt.pending_count) > 0:
            self._prompt.timer_ms = 0.0
            self._prompt.hover = False
            self._prompt.pulse = 0.0

    def _prompt_open_requested(self, *, config: CrimsonConfig, player_count: int) -> bool:
        fire_key = player_fire_keybind(config, player_index=0)
        pick_key = config.keybind_pick_perk
        if input_code_is_pressed_for_player(pick_key, player_index=0) and (
            not input_code_is_down_for_player(fire_key, player_index=0)
        ):
            return True
        return self._prompt.hover and input_primary_just_pressed(config, player_count=player_count)
