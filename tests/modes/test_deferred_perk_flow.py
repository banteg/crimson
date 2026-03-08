from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import crimson.modes.components.deferred_perk_flow as deferred_perk_flow_module
from crimson.modes.components.deferred_perk_flow import DeferredPerkFlow
from crimson.modes.components.perk_menu_controller import PerkMenuUiContext
from crimson.perks import PerkId
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


def test_prompt_flow_requests_open_from_pick_key(mocker) -> None:
    flow = DeferredPerkFlow()

    mocker.patch.object(
        deferred_perk_flow_module,
        "input_code_is_pressed_for_player",
        return_value=True,
    )
    mocker.patch.object(
        deferred_perk_flow_module,
        "player_fire_keybind",
        return_value=0x100,
    )
    mocker.patch.object(
        deferred_perk_flow_module,
        "input_code_is_down_for_player",
        return_value=False,
    )
    mocker.patch.object(
        deferred_perk_flow_module,
        "input_primary_just_pressed",
        return_value=False,
    )

    result = flow.update(
        ctx=_ctx(),
        choices=[],
        config=_config(),  # type: ignore[arg-type]
        pending_count=1,
        player_count=1,
        any_alive=True,
        paused=False,
        dt_ui_ms=16.0,
    )

    assert result.open_requested is True


def test_prompt_flow_requests_open_from_hover_click(mocker) -> None:
    flow = DeferredPerkFlow()

    mocker.patch.object(
        deferred_perk_flow_module,
        "input_code_is_pressed_for_player",
        return_value=False,
    )
    mocker.patch.object(
        deferred_perk_flow_module,
        "player_fire_keybind",
        return_value=0x100,
    )
    mocker.patch.object(
        deferred_perk_flow_module,
        "input_primary_just_pressed",
        return_value=True,
    )
    mocker.patch.object(
        deferred_perk_flow_module.PerkPromptUi,
        "rect",
        return_value=SimpleNamespace(contains=lambda _mouse: True),
    )

    result = flow.update(
        ctx=_ctx(),
        choices=[],
        config=_config(),  # type: ignore[arg-type]
        pending_count=1,
        player_count=1,
        any_alive=True,
        paused=False,
        dt_ui_ms=16.0,
    )

    assert result.open_requested is True


def test_prompt_flow_blocks_open_when_input_is_disabled(mocker) -> None:
    flow = DeferredPerkFlow()

    mocker.patch.object(
        deferred_perk_flow_module,
        "input_code_is_pressed_for_player",
        return_value=True,
    )
    mocker.patch.object(
        deferred_perk_flow_module,
        "player_fire_keybind",
        return_value=0x100,
    )
    mocker.patch.object(
        deferred_perk_flow_module,
        "input_code_is_down_for_player",
        return_value=False,
    )

    result = flow.update(
        ctx=_ctx(),
        choices=[],
        config=_config(),  # type: ignore[arg-type]
        pending_count=1,
        player_count=1,
        any_alive=True,
        paused=False,
        dt_ui_ms=16.0,
        prompt_input_enabled=False,
    )

    assert result.open_requested is False


def test_forced_open_waits_for_progress_after_pick(mocker) -> None:
    flow = DeferredPerkFlow(prompt_enabled=False)

    initial = flow.update(
        ctx=_ctx(),
        choices=[],
        config=_config(),  # type: ignore[arg-type]
        pending_count=1,
        player_count=1,
        any_alive=True,
        paused=False,
        dt_ui_ms=0.0,
        forced_open=True,
        latch_pick_until_progress=True,
    )

    assert initial.open_requested is True

    flow.open_menu()

    def _pick_once(*_args, **_kwargs) -> int:
        flow._menu.open = False
        return 0

    mocker.patch.object(flow._menu, "handle_input", side_effect=_pick_once)

    picked = flow.update(
        ctx=_ctx(),
        choices=[PerkId.SHARPSHOOTER],
        config=_config(),  # type: ignore[arg-type]
        pending_count=1,
        player_count=1,
        any_alive=True,
        paused=False,
        dt_ui_ms=0.0,
        forced_open=True,
        latch_pick_until_progress=True,
    )

    assert picked.pick_index == 0
    assert picked.open_requested is False

    held = flow.update(
        ctx=_ctx(),
        choices=[],
        config=_config(),  # type: ignore[arg-type]
        pending_count=1,
        player_count=1,
        any_alive=True,
        paused=False,
        dt_ui_ms=0.0,
        forced_open=True,
        latch_pick_until_progress=True,
    )

    assert held.open_requested is False

    flow.clear_pick_pending()

    reopened = flow.update(
        ctx=_ctx(),
        choices=[],
        config=_config(),  # type: ignore[arg-type]
        pending_count=1,
        player_count=1,
        any_alive=True,
        paused=False,
        dt_ui_ms=0.0,
        forced_open=True,
        latch_pick_until_progress=True,
    )

    assert reopened.open_requested is True
