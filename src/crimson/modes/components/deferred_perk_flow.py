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


@dataclass(slots=True, frozen=True)
class DeferredPerkFlowResult:
    open_requested: bool = False
    pick_index: int | None = None


class DeferredPerkFlow:
    def __init__(
        self,
        *,
        cancel_label: str = "Cancel",
        prompt_enabled: bool = True,
    ) -> None:
        self._prompt_enabled = bool(prompt_enabled)
        self._menu = PerkMenuController(cancel_label=cancel_label, on_close=self._handle_menu_closed)
        self.reset()

    @property
    def open(self) -> bool:
        return self._menu.open

    @property
    def active(self) -> bool:
        return self._menu.active

    def reset(self) -> None:
        self._menu.reset()
        self._pending_count = 0
        self._prompt_timer_ms = 0.0
        self._prompt_hover = False
        self._prompt_pulse = 0.0
        self._pick_pending = False

    def close(self) -> None:
        self._menu.close()

    def open_menu(self, *, play_sfx: PlaySfxFn | None = None) -> None:
        self._menu.open_menu(play_sfx=play_sfx)

    def clear_pick_pending(self) -> None:
        self._pick_pending = False

    def update(
        self,
        *,
        ctx: PerkMenuUiContext,
        choices: Sequence[PerkId],
        config: CrimsonConfig,
        pending_count: int,
        player_count: int,
        any_alive: bool,
        paused: bool,
        dt_ui_ms: float,
        prompt_scale: float = 1.0,
        prompt_input_enabled: bool = True,
        prompt_pulse_enabled: bool = True,
        menu_input_enabled: bool = True,
        forced_open: bool = False,
        latch_pick_until_progress: bool = False,
    ) -> DeferredPerkFlowResult:
        self._pending_count = int(pending_count)

        pick_index = None
        if self._menu.open and menu_input_enabled:
            pick_index = self._menu.handle_input(
                ctx,
                choices,
                dt_ui_ms=float(dt_ui_ms),
            )
            if pick_index is not None and latch_pick_until_progress:
                self._pick_pending = True

        prompt_pending = int(pending_count) > 0 and bool(any_alive)
        menu_active = self._menu.active
        open_requested = bool(forced_open) and prompt_pending and (not menu_active) and (not self._pick_pending)

        self._prompt_hover = False
        if self._prompt_enabled:
            if prompt_input_enabled and prompt_pending and (not menu_active) and (not paused):
                label = PerkPromptUi.label(config, pending_count=int(pending_count))
                if label:
                    rect = PerkPromptUi.rect(resources=ctx.resources, scale=prompt_scale)
                    self._prompt_hover = rect.contains(ctx.mouse)
                if self._prompt_open_requested(config=config, player_count=int(player_count)):
                    self._prompt_pulse = 1000.0
                    open_requested = True

            if prompt_pulse_enabled:
                pulse_delta = float(dt_ui_ms) * (6.0 if self._prompt_hover else -2.0)
                self._prompt_pulse = clamp(self._prompt_pulse + pulse_delta, 0.0, 1000.0)

            if prompt_pending and (not menu_active) and (not paused):
                timer_delta = float(dt_ui_ms)
            else:
                timer_delta = -float(dt_ui_ms)
            self._prompt_timer_ms = clamp(
                self._prompt_timer_ms + timer_delta,
                0.0,
                PERK_PROMPT_MAX_TIMER_MS,
            )

        self._menu.tick_timeline(float(dt_ui_ms))
        return DeferredPerkFlowResult(
            open_requested=bool(open_requested),
            pick_index=(None if pick_index is None else int(pick_index)),
        )

    def draw(
        self,
        *,
        ctx: PerkMenuUiContext,
        choices: Sequence[PerkId],
        pending_count: int,
        any_alive: bool,
        config: CrimsonConfig,
        ui_text_width: UiTextWidthFn,
        text_color,
        prompt_scale: float = 1.0,
        prompt_hidden: bool = False,
        menu_hidden: bool = False,
    ) -> None:
        if self._prompt_enabled:
            self._draw_prompt(
                pending_count=int(pending_count),
                any_alive=bool(any_alive),
                config=config,
                ctx=ctx,
                ui_text_width=ui_text_width,
                text_color=text_color,
                prompt_scale=float(prompt_scale),
                hidden=bool(prompt_hidden),
            )
        if not menu_hidden:
            self._menu.draw(ctx, choices)

    def _draw_prompt(
        self,
        *,
        pending_count: int,
        any_alive: bool,
        config: CrimsonConfig,
        ctx: PerkMenuUiContext,
        ui_text_width: UiTextWidthFn,
        text_color,
        prompt_scale: float,
        hidden: bool,
    ) -> None:
        if hidden or self._menu.active or (not any_alive):
            return
        if int(pending_count) <= 0:
            return
        label = PerkPromptUi.label(config, pending_count=int(pending_count))
        if not label:
            return
        PerkPromptUi.draw(
            resources=ctx.resources,
            label=label,
            timer_ms=float(self._prompt_timer_ms),
            pulse=float(self._prompt_pulse),
            ui_text_width=ui_text_width,
            text_color=text_color,
            scale=float(prompt_scale),
        )

    def _handle_menu_closed(self) -> None:
        if int(self._pending_count) > 0:
            self._prompt_timer_ms = 0.0
            self._prompt_hover = False
            self._prompt_pulse = 0.0

    def _prompt_open_requested(self, *, config: CrimsonConfig, player_count: int) -> bool:
        fire_key = player_fire_keybind(config, player_index=0)
        pick_key = config.keybind_pick_perk
        if input_code_is_pressed_for_player(pick_key, player_index=0) and (
            not input_code_is_down_for_player(fire_key, player_index=0)
        ):
            return True
        return self._prompt_hover and input_primary_just_pressed(config, player_count=player_count)
