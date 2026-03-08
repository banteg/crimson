from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import crimson.screens.chrome.runtime as chrome_runtime
from crimson.screens.chrome.runtime import (
    ActionDispatchPolicy,
    BackdropPolicy,
    ChromeRuntime,
    ChromeSpec,
    SignPolicy,
)
from grim.assets import RuntimeResources
from grim.raylib_api import rl


def _texture_stub() -> rl.Texture:
    return cast("rl.Texture", type("_TextureStub", (), {"width": 1, "height": 1})())


def _resources_stub() -> RuntimeResources:
    tex = _texture_stub()
    return cast(
        "RuntimeResources",
        SimpleNamespace(
            texture=lambda _texture_id: tex,
            small_font=SimpleNamespace(cell_size=8, widths=[8] * 256),
        ),
    )


def test_chrome_runtime_pending_rearm_restores_open_state(make_game_state) -> None:
    state = make_game_state()
    runtime = ChromeRuntime(
        state,
        spec=ChromeSpec(
            backdrop=BackdropPolicy(use_menu_ground=False),
            dispatch=ActionDispatchPolicy(mode="pending_rearm"),
            open_sfx=None,
            close_sfx=None,
        ),
    )
    runtime.open()
    runtime.chrome.timeline_ms = runtime.chrome.timeline_max_ms

    runtime.begin_close_transition("open_credits")
    runtime.chrome.timeline_ms = -1
    runtime._dispatch_close_action("open_credits")

    assert runtime.take_action() == "open_credits"
    assert runtime.chrome.closing is False
    assert runtime.chrome.timeline_ms == runtime.chrome.timeline_max_ms


def test_chrome_runtime_direct_action_drains_action_slot(make_game_state) -> None:
    state = make_game_state()
    runtime = ChromeRuntime(
        state,
        spec=ChromeSpec(
            backdrop=BackdropPolicy(use_menu_ground=False),
            dispatch=ActionDispatchPolicy(mode="direct_action"),
            open_sfx=None,
            close_sfx=None,
        ),
    )
    runtime.open()
    runtime._dispatch_close_action("back_to_previous")

    assert runtime.take_action() == "back_to_previous"
    assert runtime.take_action() is None


def test_chrome_runtime_locks_sign_and_plays_open_sfx_on_full_open(make_game_state, mocker) -> None:
    state = make_game_state(
        menu_sign_locked=False,
        audio=SimpleNamespace(music=SimpleNamespace(active_track="")),
    )
    runtime = ChromeRuntime(
        state,
        spec=ChromeSpec(
            backdrop=BackdropPolicy(use_menu_ground=False),
            sign=SignPolicy(lock_on_fully_open=True),
            open_sfx="sfx_ui_panelclick",
            open_sfx_mode="on_fully_open",
            close_sfx=None,
        ),
    )
    play_sfx = mocker.patch.object(chrome_runtime, "play_sfx")
    mocker.patch.object(chrome_runtime, "update_audio", side_effect=lambda _audio, _dt: None)
    runtime.open()

    runtime.update(0.1)
    runtime.update(0.1)
    runtime.update(0.1)

    assert state.menu_sign_locked is True
    play_sfx.assert_called_once()


def test_chrome_runtime_draw_background_uses_close_fraction_for_pause_alpha(make_game_state, mocker) -> None:
    state = make_game_state()
    pause_background = mocker.Mock()
    state.pause_background = pause_background
    runtime = ChromeRuntime(
        state,
        spec=ChromeSpec(
            backdrop=BackdropPolicy(
                entity_alpha_mode="close_timeline_fraction",
                entity_alpha_duration_ms=500,
                entity_alpha_action="back_to_menu",
            ),
            open_sfx=None,
            close_sfx=None,
        ),
    )
    runtime.open()
    runtime.chrome.closing = True
    runtime.chrome.close_action = "back_to_menu"
    runtime.chrome.timeline_ms = 250

    mocker.patch.object(chrome_runtime.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    runtime.draw_background()

    pause_background.draw_pause_background.assert_called_once_with(entity_alpha=0.5)


def test_chrome_runtime_frame_uses_runtime_resources(make_game_state) -> None:
    state = make_game_state()
    state.resources = _resources_stub()
    runtime = ChromeRuntime(
        state,
        spec=ChromeSpec(
            backdrop=BackdropPolicy(use_menu_ground=False),
            open_sfx=None,
            close_sfx=None,
        ),
    )
    runtime.open()

    frame = runtime.frame()

    assert frame.timeline_ms == 0
    assert frame.interactive is False
