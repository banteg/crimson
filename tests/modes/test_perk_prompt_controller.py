from __future__ import annotations

from types import SimpleNamespace

import crimson.modes.components.perk_prompt_controller as perk_prompt_controller_module
from crimson.modes.components.perk_prompt_controller import PerkPromptState
from grim.config import CrimsonConfig
from grim.raylib_api import rl


def _config() -> CrimsonConfig:
    return SimpleNamespace(  # type: ignore[return-value]
        keybind_pick_perk=0x101,
        ui_info_texts=True,
    )


def _resources() -> object:
    return SimpleNamespace(texture=lambda _texture_id: SimpleNamespace(width=64, height=32))


def test_perk_prompt_state_requests_open_from_pick_key(mocker) -> None:
    prompt = PerkPromptState()

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

    opened = prompt.update(
        config=_config(),
        resources=_resources(),  # type: ignore[arg-type]
        mouse=rl.Vector2(0.0, 0.0),
        pending_count=1,
        player_count=1,
        any_alive=True,
        menu_active=False,
        paused=False,
        dt_ui_ms=16.0,
    )

    assert opened is True
    assert prompt.pulse == 968.0


def test_perk_prompt_state_requests_open_from_hover_click(mocker) -> None:
    prompt = PerkPromptState()

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

    opened = prompt.update(
        config=_config(),
        resources=_resources(),  # type: ignore[arg-type]
        mouse=rl.Vector2(0.0, 0.0),
        pending_count=1,
        player_count=1,
        any_alive=True,
        menu_active=False,
        paused=False,
        dt_ui_ms=16.0,
    )

    assert opened is True
    assert prompt.hover is True


def test_perk_prompt_state_blocks_open_when_input_is_disabled(mocker) -> None:
    prompt = PerkPromptState()

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

    opened = prompt.update(
        config=_config(),
        resources=_resources(),  # type: ignore[arg-type]
        mouse=rl.Vector2(0.0, 0.0),
        pending_count=1,
        player_count=1,
        any_alive=True,
        menu_active=False,
        paused=False,
        dt_ui_ms=16.0,
        allow_input=False,
    )

    assert opened is False
    assert prompt.pulse == 0.0
