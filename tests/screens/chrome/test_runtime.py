from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

import crimson.screens.chrome.runtime as chrome_runtime
from crimson.game.types import BackToMenu, BackToPrevious, FrontRouteId, OpenFrontRoute
from crimson.screens.chrome.runtime import (
    BackdropPolicy,
    ChromeRuntime,
    ChromeSpec,
    CloseTimelineEntityAlpha,
    DirectActionDispatch,
    DispatchPolicy,
    EntityAlphaPolicy,
    MusicPolicy,
    NoOpenSfx,
    OpenSfxPolicy,
    PendingOnceDispatch,
    PlayOpenSfxOnFullyOpen,
    PlayOpenSfxOnOpen,
    SignPolicy,
)


def test_chrome_runtime_pending_once_drains_pending_action(make_game_state) -> None:
    state = make_game_state()
    runtime = ChromeRuntime(
        state,
        spec=ChromeSpec(
            backdrop=BackdropPolicy(use_menu_ground=False),
            dispatch=PendingOnceDispatch(),
            open_sfx=NoOpenSfx(),
            close_sfx=None,
        ),
    )
    runtime.open()
    runtime._dispatch_close_action(OpenFrontRoute(FrontRouteId.OPEN_CREDITS))

    assert runtime.take_action() == OpenFrontRoute(FrontRouteId.OPEN_CREDITS)
    assert runtime.take_action() is None


def test_chrome_runtime_direct_action_drains_action_slot(make_game_state) -> None:
    state = make_game_state()
    runtime = ChromeRuntime(
        state,
        spec=ChromeSpec(
            backdrop=BackdropPolicy(use_menu_ground=False),
            dispatch=DirectActionDispatch(),
            open_sfx=NoOpenSfx(),
            close_sfx=None,
        ),
    )
    runtime.open()
    runtime._dispatch_close_action(BackToPrevious())

    assert runtime.take_action() == BackToPrevious()
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
            open_sfx=PlayOpenSfxOnFullyOpen(),
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
                entity_alpha=CloseTimelineEntityAlpha(duration_ms=500, action=BackToMenu()),
            ),
            open_sfx=NoOpenSfx(),
            close_sfx=None,
        ),
    )
    runtime.open()
    runtime.chrome.closing = True
    runtime.chrome.close_action = BackToMenu()
    runtime.chrome.timeline_ms = 250

    mocker.patch.object(chrome_runtime.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    runtime.draw_background()

    pause_background.draw_pause_background.assert_called_once_with(entity_alpha=0.5)


def test_chrome_runtime_draw_background_keeps_close_fraction_opaque_while_opening(make_game_state, mocker) -> None:
    state = make_game_state()
    pause_background = mocker.Mock()
    state.pause_background = pause_background
    runtime = ChromeRuntime(
        state,
        spec=ChromeSpec(
            backdrop=BackdropPolicy(
                entity_alpha=CloseTimelineEntityAlpha(duration_ms=500),
            ),
            open_sfx=NoOpenSfx(),
            close_sfx=None,
        ),
    )
    runtime.open()
    runtime.chrome.timeline_ms = 250

    mocker.patch.object(chrome_runtime.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    runtime.draw_background()

    pause_background.draw_pause_background.assert_called_once_with(entity_alpha=1.0)


def test_chrome_runtime_begin_close_transition_runs_hook_once(make_game_state, mocker) -> None:
    state = make_game_state()
    runtime = ChromeRuntime(
        state,
        spec=ChromeSpec(
            backdrop=BackdropPolicy(use_menu_ground=False),
            open_sfx=NoOpenSfx(),
            close_sfx=None,
        ),
    )
    runtime.open()
    before_close = mocker.Mock()

    runtime.begin_close_transition(OpenFrontRoute(FrontRouteId.OPEN_CREDITS), before_close=before_close)
    runtime.begin_close_transition(OpenFrontRoute(FrontRouteId.OPEN_OPTIONS), before_close=before_close)

    before_close.assert_called_once_with(OpenFrontRoute(FrontRouteId.OPEN_CREDITS))
    assert runtime.chrome.closing is True
    assert runtime.chrome.close_action == OpenFrontRoute(FrontRouteId.OPEN_CREDITS)


def test_backdrop_policy_rejects_raw_entity_alpha() -> None:
    with pytest.raises(TypeError, match="BackdropPolicy.entity_alpha"):
        BackdropPolicy(entity_alpha=cast(EntityAlphaPolicy, "close_timeline_fraction"))


def test_close_timeline_entity_alpha_rejects_non_int_duration() -> None:
    with pytest.raises(TypeError, match="CloseTimelineEntityAlpha.duration_ms"):
        CloseTimelineEntityAlpha(duration_ms=cast(int, "500"))


def test_close_timeline_entity_alpha_rejects_non_positive_duration() -> None:
    with pytest.raises(ValueError, match="CloseTimelineEntityAlpha.duration_ms"):
        CloseTimelineEntityAlpha(duration_ms=0)


def test_chrome_spec_rejects_raw_dispatch_and_open_sfx() -> None:
    with pytest.raises(TypeError, match="ChromeSpec.dispatch"):
        ChromeSpec(dispatch=cast(DispatchPolicy, "pending_once"))
    with pytest.raises(TypeError, match="ChromeSpec.open_sfx"):
        ChromeSpec(open_sfx=cast(OpenSfxPolicy, "on_open"))


def test_open_sfx_policy_rejects_non_string_sfx_id() -> None:
    with pytest.raises(TypeError, match="PlayOpenSfxOnOpen.sfx_id"):
        PlayOpenSfxOnOpen(sfx_id=cast(str, 123))


def test_music_policy_rejects_non_bool_refresh_flag() -> None:
    with pytest.raises(TypeError, match="MusicPolicy.refresh_while_open"):
        MusicPolicy(refresh_while_open=cast(bool, "yes"))


def test_sign_policy_rejects_non_tuple_unlock_actions() -> None:
    with pytest.raises(TypeError, match="SignPolicy.unlock_on_actions"):
        SignPolicy(unlock_on_actions=cast(Any, ("ok", 1)))


def test_backdrop_policy_rejects_non_bool_pause_background_flag() -> None:
    with pytest.raises(TypeError, match="BackdropPolicy.allow_pause_background"):
        BackdropPolicy(allow_pause_background=cast(bool, "yes"))


def test_chrome_spec_rejects_invalid_scalar_fields() -> None:
    with pytest.raises(TypeError, match="ChromeSpec.timeline_max_ms"):
        ChromeSpec(timeline_max_ms=cast(int, "300"))
    with pytest.raises(TypeError, match="ChromeSpec.close_sfx"):
        ChromeSpec(close_sfx=cast(str | None, 123))
    with pytest.raises(TypeError, match="ChromeSpec.fade_to_game_actions"):
        ChromeSpec(fade_to_game_actions=cast(Any, frozenset({"start_quest"})))
