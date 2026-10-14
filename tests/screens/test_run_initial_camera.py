from __future__ import annotations

import pytest

from crimson import local_input
from crimson.game_modes import GameMode
from crimson.quests.dsl import build_custom_quest
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.replay.input_codec import unpack_player_input
from crimson.replay.ranked import RankedTickMonitor
from crimson.screens.actions import StartRun
from grim import canvas
from grim.geom import Vec2
from tests.support.audio import HeadlessAudio
from tests.support.screens import start_run, update_frame

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")


@pytest.mark.parametrize("size", [Vec2(1024, 768), Vec2(1920, 1080), Vec2(800, 600)])
@pytest.mark.parametrize("custom", [False, True])
def test_first_frame_cursor_at_top_left_stays_inside_ranked_view(
    make_game_state,
    headless_resources,
    mocker,
    size,
    custom,
):
    mocker.patch.object(canvas, "width", return_value=int(size.x))
    mocker.patch.object(canvas, "height", return_value=int(size.y))
    mocker.patch.object(canvas, "mouse_position", return_value=Vec2().to_rl())
    state = make_game_state(resources=headless_resources, audio=HeadlessAudio(mocker).state)
    # Custom quests use the canonical view even with the Ranked box off.
    state.ranked = not custom
    quest = build_custom_quest('quest "Camera Probe" version 1\nat 10s:\n    spawn spider.splitter at (512, -64)')
    request = StartRun(GameMode.QUESTS, custom_quest=quest) if custom else StartRun(GameMode.SURVIVAL)
    _navigator, run = start_run(state, request)
    world = run.world
    expected_aim = run.player.pos - run.world_runtime.view_transform().screen_size * 0.5

    # A long first frame can record several ticks before presentation updates the camera.
    update_frame(run, state, dt=0.1)
    recorder = run._replay_recorder
    assert recorder is not None
    assert run._replay_result is not None
    replay = recorder.finish(run._replay_result)
    assert len(replay.ticks) > 1
    first_input = unpack_player_input(replay.ticks[0].inputs[0])
    assert first_input.aim == expected_aim
    monitor = RankedTickMonitor(replay)
    monitor.before_tick(0, world, 1.0 / 60.0)
    assert not monitor.reasons


@pytest.mark.parametrize(("cursor_y", "away_keys"), [(0.0, {0x1F, 0xD0}), (767.0, {0x11, 0xC8})])
def test_long_frame_reads_the_cursor_through_each_ticks_camera(
    make_game_state,
    headless_resources,
    mocker,
    cursor_y,
    away_keys,
):
    mocker.patch.object(canvas, "width", return_value=1024)
    mocker.patch.object(canvas, "height", return_value=768)
    mocker.patch.object(canvas, "mouse_position", return_value=Vec2(512.0, cursor_y).to_rl())
    # Walk away from a cursor held on the screen's edge, so the camera moves between ticks.
    mocker.patch.object(local_input, "input_code_is_down", side_effect=lambda code, player_index=0: code in away_keys)
    state = make_game_state(resources=headless_resources, audio=HeadlessAudio(mocker).state)
    state.ranked = True
    _navigator, run = start_run(state, StartRun(GameMode.SURVIVAL))

    for dt in [1.0 / 60.0] * 20 + [0.1]:
        update_frame(run, state, dt=dt)
    recorder = run._replay_recorder
    assert recorder is not None
    assert run._replay_result is not None
    replay = recorder.finish(run._replay_result)
    assert len(replay.ticks) > 21
    monitor = RankedTickMonitor(replay)
    PlaybackDriver(replay).run(observer=monitor)
    assert not monitor.reasons
