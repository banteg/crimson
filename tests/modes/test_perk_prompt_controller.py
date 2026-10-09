from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

import crimson.modes.components.perk_prompt_controller as perk_prompt_controller_module
from crimson.modes.components.perk_menu_controller import PerkMenuUiContext
from crimson.modes.components.perk_prompt_controller import PerkPromptState
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.assets import RuntimeResources
from grim.config import default_crimson_cfg
from grim.fonts.small import SmallFontData
from grim.geom import Vec2
from grim.raylib_api import rl


def _config():
    config = default_crimson_cfg()
    config.controls.pick_perk_code = 0x101
    config.gameplay.show_info_texts = True
    return config


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


def _ctx() -> PerkMenuUiContext:
    return PerkMenuUiContext(
        player=PlayerState(index=0, pos=Vec2()),
        perks=PerkCounts(),
        violence_disabled=0,
        resources=_resources(),
        mouse=rl.Vector2(0.0, 0.0),
    )


def _patch_input(mocker, *, pick_down: bool = False, keys: tuple[int, ...] = (), click: bool = False) -> None:
    mocker.patch.object(perk_prompt_controller_module, "input_code_is_down", return_value=pick_down)
    mocker.patch.object(perk_prompt_controller_module.rl, "is_key_pressed", side_effect=lambda key: key in keys)
    mocker.patch.object(perk_prompt_controller_module.rl, "is_mouse_button_down", return_value=False)
    mocker.patch.object(perk_prompt_controller_module, "input_primary_just_pressed", return_value=click)


def _poll(prompt: PerkPromptState, *, menu_active: bool = False) -> bool:
    return prompt.poll_open_request(
        ctx=_ctx(),
        config=_config(),
        pending_count=1,
        alive=True,
        paused=False,
        menu_active=menu_active,
        player_count=1,
    )


@pytest.mark.parametrize("key", [rl.KeyboardKey.KEY_SPACE, rl.KeyboardKey.KEY_KP_ADD])
def test_prompt_opens_on_space_and_keypad_plus(mocker, key: int) -> None:
    # Native `gameplay_update_and_render` also takes DIK 57 (Space) and 78 (keypad +).
    _patch_input(mocker, keys=(key,))
    assert _poll(PerkPromptState())


def test_prompt_ignores_input_while_the_mouse_was_held_or_the_menu_is_up(mocker) -> None:
    _patch_input(mocker, pick_down=True)
    assert not _poll(PerkPromptState(mouse_down=True))
    assert not _poll(PerkPromptState(), menu_active=True)
