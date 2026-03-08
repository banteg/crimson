from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import cast

import crimson.modes.components.perk_prompt_controller as perk_prompt_controller_module
from crimson.modes.components.perk_menu_controller import PerkMenuContext, PerkMenuController
from crimson.modes.components.perk_prompt_controller import PerkPromptController
from grim.config import CrimsonConfig


@dataclass
class _MenuStub:
    events: list[str] = field(default_factory=list)
    open: bool = False
    active: bool = False
    handle_input_calls: list[tuple[float, float]] = field(default_factory=list)
    timeline_ticks: list[float] = field(default_factory=list)

    def handle_input(self, _ctx, *, dt: float, dt_ui_ms: float) -> None:
        self.handle_input_calls.append((float(dt), float(dt_ui_ms)))

    def open_if_available(self, _ctx) -> bool:
        self.events.append("open")
        self.open = True
        self.active = True
        return True

    def tick_timeline(self, dt_ui_ms: float) -> None:
        self.timeline_ticks.append(float(dt_ui_ms))


def _config() -> CrimsonConfig:
    return cast(
        CrimsonConfig,
        SimpleNamespace(
            keybind_pick_perk=0x101,
            ui_info_texts=True,
        ),
    )


def _ctx() -> PerkMenuContext:
    resources = SimpleNamespace(texture=lambda _texture_id: SimpleNamespace(width=64, height=32))
    return cast(
        PerkMenuContext,
        SimpleNamespace(
            resources=resources,
            mouse=SimpleNamespace(x=0.0, y=0.0),
            player_count=1,
        ),
    )


def test_perk_prompt_controller_opens_menu_from_pick_key_before_success_callback(mocker) -> None:
    controller = PerkPromptController(pending_count=lambda: 1)
    events: list[str] = []
    menu = _MenuStub(events=events)

    mocker.patch.object(
        perk_prompt_controller_module,
        "input_code_is_pressed_for_player",
        return_value=True,
    )
    mocker.patch.object(
        perk_prompt_controller_module,
        "config_keybinds_for_player",
        return_value=(0, 0, 0, 0, 0x100),
    )
    mocker.patch.object(
        perk_prompt_controller_module,
        "input_code_is_down_for_player",
        return_value=False,
    )
    mocker.patch.object(
        perk_prompt_controller_module,
        "input_primary_just_pressed",
        return_value=False,
    )

    controller.update(
        menu=cast(PerkMenuController, menu),
        ctx=_ctx(),
        config=_config(),
        dt=1.0 / 60.0,
        dt_ui_ms=16.0,
        any_alive=True,
        paused=False,
        on_open_attempt=lambda: events.append("attempt"),
        on_open_success=lambda: events.append("success"),
    )

    assert events == ["attempt", "open", "success"]
    assert menu.timeline_ticks == [16.0]


def test_perk_prompt_controller_opens_menu_from_prompt_hover_click(mocker) -> None:
    controller = PerkPromptController(pending_count=lambda: 1)
    events: list[str] = []
    menu = _MenuStub(events=events)

    mocker.patch.object(
        perk_prompt_controller_module,
        "input_code_is_pressed_for_player",
        return_value=False,
    )
    mocker.patch.object(
        perk_prompt_controller_module,
        "config_keybinds_for_player",
        return_value=(0, 0, 0, 0, 0x100),
    )
    mocker.patch.object(
        perk_prompt_controller_module,
        "input_primary_just_pressed",
        return_value=True,
    )
    mocker.patch.object(
        perk_prompt_controller_module.PerkPromptUi,
        "rect",
        return_value=SimpleNamespace(contains=lambda _mouse: True),
    )

    controller.update(
        menu=cast(PerkMenuController, menu),
        ctx=_ctx(),
        config=_config(),
        dt=1.0 / 60.0,
        dt_ui_ms=16.0,
        any_alive=True,
        paused=False,
        on_open_attempt=lambda: events.append("attempt"),
        on_open_success=lambda: events.append("success"),
    )

    assert events == ["attempt", "open", "success"]


def test_perk_prompt_controller_blocks_open_when_input_is_disabled(mocker) -> None:
    controller = PerkPromptController(pending_count=lambda: 1)
    menu = _MenuStub()
    events: list[str] = []

    mocker.patch.object(
        perk_prompt_controller_module,
        "input_code_is_pressed_for_player",
        return_value=True,
    )
    mocker.patch.object(
        perk_prompt_controller_module,
        "config_keybinds_for_player",
        return_value=(0, 0, 0, 0, 0x100),
    )
    mocker.patch.object(
        perk_prompt_controller_module,
        "input_code_is_down_for_player",
        return_value=False,
    )

    controller.update(
        menu=cast(PerkMenuController, menu),
        ctx=_ctx(),
        config=_config(),
        dt=1.0 / 60.0,
        dt_ui_ms=16.0,
        any_alive=True,
        paused=False,
        allow_input=False,
        on_open_attempt=lambda: events.append("attempt"),
        on_open_success=lambda: events.append("success"),
    )

    assert events == []
    assert menu.handle_input_calls == []
    assert menu.timeline_ticks == [16.0]
