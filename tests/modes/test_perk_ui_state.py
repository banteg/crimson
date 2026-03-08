from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import crimson.modes.components.perk_ui_state as perk_ui_state_module
from crimson.modes.components.perk_menu_controller import PerkMenuUiContext
from crimson.modes.components.perk_ui_state import PerkUiState
from crimson.sim.state_types import PlayerState
from grim.assets import RuntimeResources
from grim.fonts.small import SmallFontData
from grim.geom import Vec2
from grim.raylib_api import rl


def _config():
    return SimpleNamespace(
        keybind_pick_perk=0x101,
        ui_info_texts=True,
    )


def _texture() -> rl.Texture:
    return rl.Texture()


def _dummy_font() -> SmallFontData:
    return SmallFontData(widths=[8] * 256, texture=_texture(), cell_size=16, grid=16)


def _resources() -> RuntimeResources:
    texture = _texture()
    return cast(
        "RuntimeResources",
        SimpleNamespace(
            texture=lambda _texture_id: texture,
            small_font=_dummy_font(),
        ),
    )


def _player() -> PlayerState:
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts = [0] * 128
    return player


def _ctx() -> PerkMenuUiContext:
    return PerkMenuUiContext(
        player=_player(),
        gore_disabled=0,
        preserve_bugs=False,
        resources=_resources(),
        mouse=rl.Vector2(0.0, 0.0),
    )


def test_prompt_open_request_from_pick_key(mocker) -> None:
    perk_ui = PerkUiState()
    perk_ui.begin_prompt_frame(pending_count=1)

    mocker.patch.object(
        perk_ui_state_module,
        "input_code_is_pressed_for_player",
        return_value=True,
    )
    mocker.patch.object(
        perk_ui_state_module,
        "player_fire_keybind",
        return_value=0x100,
    )
    mocker.patch.object(
        perk_ui_state_module,
        "input_code_is_down_for_player",
        return_value=False,
    )
    mocker.patch.object(
        perk_ui_state_module,
        "input_primary_just_pressed",
        return_value=False,
    )

    assert perk_ui.poll_prompt_open_request(
        ctx=_ctx(),
        config=_config(),  # type: ignore[arg-type]
        pending_count=1,
        player_count=1,
        any_alive=True,
        paused=False,
    )


def test_prompt_open_request_from_hover_click(mocker) -> None:
    perk_ui = PerkUiState()
    perk_ui.begin_prompt_frame(pending_count=1)

    mocker.patch.object(
        perk_ui_state_module,
        "input_code_is_pressed_for_player",
        return_value=False,
    )
    mocker.patch.object(
        perk_ui_state_module,
        "player_fire_keybind",
        return_value=0x100,
    )
    mocker.patch.object(
        perk_ui_state_module,
        "input_primary_just_pressed",
        return_value=True,
    )
    mocker.patch.object(
        perk_ui_state_module.PerkPromptUi,
        "rect",
        return_value=SimpleNamespace(contains=lambda _mouse: True),
    )

    assert perk_ui.poll_prompt_open_request(
        ctx=_ctx(),
        config=_config(),  # type: ignore[arg-type]
        pending_count=1,
        player_count=1,
        any_alive=True,
        paused=False,
    )


def test_begin_prompt_frame_clears_stale_hover_before_pulse_tick() -> None:
    perk_ui = PerkUiState()
    perk_ui._prompt.hover = True
    perk_ui._prompt.pulse = 100.0

    perk_ui.begin_prompt_frame(pending_count=1)
    perk_ui.tick_prompt_pulse(16.0)

    assert perk_ui._prompt.hover is False
    assert perk_ui._prompt.pulse == 68.0
