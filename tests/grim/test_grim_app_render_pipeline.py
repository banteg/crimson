from __future__ import annotations

from typing import Any

import pytest

import grim.app as grim_app
from grim.raylib_api import rd, rl


class _FakeRl:
    ConfigFlags = rl.ConfigFlags
    KeyboardKey = rl.KeyboardKey
    ffi = rl.ffi

    def __init__(self) -> None:
        self.window_should_close_calls = 0
        self.begin_calls = 0
        self.end_calls = 0
        self.close_calls = 0
        self.init_args: tuple[int, int, str] | None = None
        self.target_fps: int | None = None
        self.keys_by_frame: list[set[int]] = []
        self.frame = -1
        self.borderless = False
        self.window_size = (0, 0)
        self.saved_window_size = (0, 0)
        self.restored_sizes: list[tuple[int, int]] = []
        self.decoration_restores: list[tuple[bool, int, int]] = []

    def set_config_flags(self, _: int) -> None:
        return None

    def init_window(self, width: int, height: int, title: str) -> None:
        self.init_args = (width, height, title)
        self.window_size = (width, height)

    def glfw_get_window_size(self, _window: Any, width: Any, height: Any) -> None:
        width[0], height[0] = self.window_size

    def glfw_set_window_size(self, _window: Any, width: int, height: int) -> None:
        self.window_size = (width, height)
        self.restored_sizes.append(self.window_size)

    def glfw_set_window_attrib(self, _window: Any, attrib: int, value: int) -> None:
        self.decoration_restores.append((self.borderless, attrib, value))

    def set_window_state(self, flags: int) -> None:
        if flags & rl.ConfigFlags.FLAG_BORDERLESS_WINDOWED_MODE:
            self.toggle_borderless_windowed()

    def set_exit_key(self, _: int) -> None:
        return None

    def glfw_get_current_context(self) -> Any:
        return rl.ffi.NULL

    def glfw_set_key_callback(self, _window: Any, hook: Any) -> Any:
        self.key_hook = hook
        self.raylib_key_events: list[tuple[int, int]] = []
        return lambda _window, key, _scancode, action, _mods: self.raylib_key_events.append((key, action))

    def set_target_fps(self, fps: int) -> None:
        self.target_fps = fps

    def window_should_close(self) -> bool:
        self.window_should_close_calls += 1
        return self.window_should_close_calls > 1

    def get_frame_time(self) -> float:
        self.frame += 1
        return 1.0 / 60.0

    def is_window_focused(self) -> bool:
        return True

    def _keys(self) -> set[int]:
        return self.keys_by_frame[self.frame] if self.frame < len(self.keys_by_frame) else set()

    def is_key_pressed(self, key: int) -> bool:
        return key in self._keys()

    def is_key_down(self, key: int) -> bool:
        return key in self._keys()

    def toggle_borderless_windowed(self) -> None:
        if self.borderless:
            # Model raylib incorrectly applying 150% DPI again on exit.
            self.window_size = tuple(int(size * 1.5) for size in self.saved_window_size)
        else:
            self.saved_window_size = self.window_size
            self.window_size = (2560, 1440)
        self.borderless = not self.borderless

    def is_window_state(self, _: int) -> bool:
        return self.borderless

    def get_render_width(self) -> int:
        return 800

    def get_render_height(self) -> int:
        return 450

    def begin_drawing(self) -> None:
        self.begin_calls += 1

    def end_drawing(self) -> None:
        self.end_calls += 1

    def close_window(self) -> None:
        self.close_calls += 1


class _CanvasStub:
    def __init__(self, width: int, height: int) -> None:
        self.size = (width, height)

    def fit(self) -> None:
        return None

    def draw(self, draw_frame: Any) -> None:
        draw_frame()

    def close(self) -> None:
        return None


class _ViewSpy:
    def __init__(self) -> None:
        self.open_calls = 0
        self.update_dts: list[float] = []
        self.draw_calls = 0
        self.close_calls = 0

    def open(self) -> None:
        self.open_calls += 1

    def update(self, dt: float) -> None:
        self.update_dts.append(dt)

    def draw(self) -> None:
        self.draw_calls += 1

    def close(self) -> None:
        self.close_calls += 1


class _PipelineSpy:
    def __init__(
        self,
        *,
        sink: Any,
        on_resize: Any = None,
        draw_scope: Any = None,
    ) -> None:
        self.sink = sink
        self.on_resize = on_resize
        self.draw_scope = draw_scope
        self.draw_calls: list[tuple[int, int]] = []
        self.present_calls = 0
        self.close_calls = 0

    def draw(self, *, draw_frame: Any, width: int, height: int) -> None:
        self.draw_calls.append((width, height))
        draw_frame()

    def present(self) -> None:
        self.present_calls += 1

    def close(self) -> None:
        self.close_calls += 1


def test_run_view_uses_explicit_quit_and_screenshot_callbacks(mocker, tmp_path) -> None:
    fake_rl = _FakeRl()
    view = _ViewSpy()
    mocker.patch.object(grim_app, "rl", fake_rl)
    mocker.patch.object(grim_app, "Canvas", _CanvasStub)
    mocker.patch.object(grim_app, "WindowSink")
    mocker.patch.object(grim_app, "RaylibDrawScope")
    mocker.patch.object(grim_app, "RenderPipeline", _PipelineSpy)
    mocker.patch.object(fake_rl, "window_should_close", return_value=False)
    screenshot = mocker.patch.object(grim_app, "_save_screenshot")
    quit_requested = mocker.Mock(side_effect=[False, True])
    screenshot_requested = mocker.Mock(side_effect=[True, False])
    screenshot_saved = mocker.Mock()
    grim_app.run_view(
        view,
        hooks=grim_app.RunViewHooks(
            should_close=quit_requested,
            consume_screenshot_request=screenshot_requested,
            screenshot_saved=screenshot_saved,
        ),
        screenshot_dir=tmp_path,
    )
    assert view.draw_calls == 2
    assert len(view.update_dts) == 2
    assert screenshot.call_count == 1
    assert screenshot.call_args.args[0] == tmp_path / "shot_000.png"
    screenshot_saved.assert_called_once_with(tmp_path / "shot_000.png")
    assert quit_requested.call_count == screenshot_requested.call_count == 2
    assert view.close_calls == fake_rl.close_calls == 1


def test_run_view_alt_enter_toggles_fullscreen_without_updating_the_view(mocker) -> None:
    fake_rl = _FakeRl()
    fake_rl.keys_by_frame = [{rl.KeyboardKey.KEY_LEFT_ALT, rl.KeyboardKey.KEY_ENTER}, {rl.KeyboardKey.KEY_ENTER}]
    view = _ViewSpy()
    mocker.patch.object(grim_app, "rl", fake_rl)
    mocker.patch.object(grim_app, "Canvas", _CanvasStub)
    mocker.patch.object(grim_app, "WindowSink")
    mocker.patch.object(grim_app, "RaylibDrawScope")
    mocker.patch.object(grim_app, "RenderPipeline", _PipelineSpy)
    mocker.patch.object(fake_rl, "window_should_close", side_effect=[False, False, True])
    fullscreen_changed = mocker.Mock()

    grim_app.run_view(view, hooks=grim_app.RunViewHooks(fullscreen_changed=fullscreen_changed))

    fullscreen_changed.assert_called_once_with(True)
    # The toggle frame's Enter press never reaches the view; plain Enter on the next frame does.
    assert len(view.update_dts) == 1
    assert view.draw_calls == 2


def test_screenshot_names_skip_existing_shots(tmp_path) -> None:
    (tmp_path / "shot_000.png").touch()
    (tmp_path / "shot_001.png").touch()

    assert grim_app._next_screenshot_name(tmp_path, 0) == ("shot_002.png", 3)
    assert grim_app._next_screenshot_name(tmp_path, 1000) == ("shot_1000.png", 1001)


@pytest.mark.parametrize("start_fullscreen", [False, True])
def test_run_view_preserves_window_size_across_repeated_fullscreen_cycles(mocker, start_fullscreen) -> None:
    fake_rl = _FakeRl()
    fake_rl.keys_by_frame = [{rl.KeyboardKey.KEY_LEFT_ALT, rl.KeyboardKey.KEY_ENTER}] * 6
    view = _ViewSpy()
    mocker.patch.object(grim_app, "rl", fake_rl)
    mocker.patch.object(grim_app, "Canvas", _CanvasStub)
    mocker.patch.object(grim_app, "WindowSink")
    mocker.patch.object(grim_app, "RaylibDrawScope")
    mocker.patch.object(grim_app, "RenderPipeline", _PipelineSpy)
    mocker.patch.object(fake_rl, "window_should_close", side_effect=[False] * 6 + [True])
    fullscreen_changed = mocker.Mock()

    grim_app.run_view(
        view,
        width=640,
        height=480,
        window_state=rl.ConfigFlags.FLAG_BORDERLESS_WINDOWED_MODE if start_fullscreen else 0,
        hooks=grim_app.RunViewHooks(fullscreen_changed=fullscreen_changed),
    )

    assert fake_rl.restored_sizes == [(640, 480)] * 3
    assert fake_rl.decoration_restores == [(False, rd.GLFW_DECORATED, rd.GLFW_TRUE)] * 3
    assert fullscreen_changed.call_args_list == [mocker.call(not start_fullscreen), mocker.call(start_fullscreen)] * 3


def test_run_view_restores_the_window_size_from_before_fullscreen_entry(mocker) -> None:
    fake_rl = _FakeRl()
    fake_rl.keys_by_frame = [set(), {rl.KeyboardKey.KEY_LEFT_ALT, rl.KeyboardKey.KEY_ENTER}] * 2
    view = _ViewSpy()
    mocker.patch.object(grim_app, "rl", fake_rl)
    mocker.patch.object(grim_app, "Canvas", _CanvasStub)
    mocker.patch.object(grim_app, "WindowSink")
    mocker.patch.object(grim_app, "RaylibDrawScope")
    mocker.patch.object(grim_app, "RenderPipeline", _PipelineSpy)
    mocker.patch.object(fake_rl, "window_should_close", side_effect=[False] * 4 + [True])

    def resize_before_entry(_dt: float) -> None:
        if not fake_rl.borderless:
            fake_rl.window_size = (1000, 700)

    mocker.patch.object(view, "update", side_effect=resize_before_entry)
    grim_app.run_view(view, width=640, height=480)

    assert fake_rl.restored_sizes == [(1000, 700)]


def test_raylib_sees_the_screenshot_key_only_after_the_frame_ends(mocker) -> None:
    # raylib's EndDrawing saves its own screenshot when F12 went down in its input poll.
    fake_rl = _FakeRl()
    mocker.patch.object(grim_app, "rl", fake_rl)
    held = grim_app._HeldKey(rl.KeyboardKey.KEY_F12)
    press, release = 1, 0

    for key, action in ((rl.KeyboardKey.KEY_F12, press), (rl.KeyboardKey.KEY_A, press), (rl.KeyboardKey.KEY_F12, release)):
        fake_rl.key_hook(rl.ffi.NULL, key, 0, action, 0)
    assert fake_rl.raylib_key_events == [(rl.KeyboardKey.KEY_A, press)]

    held.release()
    assert fake_rl.raylib_key_events == [
        (rl.KeyboardKey.KEY_A, press),
        (rl.KeyboardKey.KEY_F12, press),
        (rl.KeyboardKey.KEY_F12, release),
    ]


def test_run_view_updates_edr_after_mode_changes_and_resets_on_close(mocker) -> None:
    from contextlib import nullcontext

    fake_rl = _FakeRl()
    view = _ViewSpy()
    mocker.patch.object(grim_app, "rl", fake_rl)
    mocker.patch.object(grim_app, "Canvas", _CanvasStub)
    mocker.patch.object(grim_app, "WindowSink")
    mocker.patch.object(grim_app, "RaylibDrawScope")
    mocker.patch.object(grim_app, "RenderPipeline", _PipelineSpy)
    mocker.patch.object(fake_rl, "window_should_close", side_effect=[False, False, True])
    reserve = mocker.patch.object(grim_app, "float_backbuffer", return_value=nullcontext())
    activate = mocker.patch.object(grim_app, "activate_edr_window")
    reset = mocker.patch.object(grim_app, "reset_edr_window")
    requested = False

    def update(_dt: float) -> None:
        nonlocal requested
        requested = not requested

    mocker.patch.object(view, "update", side_effect=update)
    grim_app.run_view(view, hooks=grim_app.RunViewHooks(wants_edr=lambda: requested))
    reserve.assert_called_once_with(enabled=True)
    # Initial classic, then RTX and classic again; the new mode applies to that frame.
    assert activate.call_args_list == [mocker.call(False), mocker.call(True), mocker.call(False)]
    assert reset.call_count == 2
