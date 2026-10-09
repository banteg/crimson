from __future__ import annotations

from itertools import count
from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.render.terrain_fx import FxQueueTextures
from crimson.replay.driver.playback_driver import build_runtime_playback_driver
from crimson.replay.driver.prepare import ReplayPreparation
from crimson.sim.run_spec import RunSpec
from crimson.world import terrain_history
from crimson.world.render_resources import RenderResources
from crimson.world.terrain_history import TerrainHistory
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from tests.support.factories import player_input
from tests.support.replay_runner_helpers import record_replay

pytestmark = pytest.mark.usefixtures("headless_window")


def _target(ids: count) -> rl.RenderTexture:
    target = rl.RenderTexture()
    target.id = next(ids)
    target.texture.width = target.texture.height = 64
    return target


@pytest.fixture
def resources(mocker) -> RenderResources:
    """The run's ground as a render target without a GPU: targets load as plain structs and nothing draws."""
    ids = count(1)
    mocker.patch.object(rl, "load_render_texture", side_effect=lambda *_: _target(ids))
    mocker.patch.object(rl, "unload_render_texture")
    mocker.patch.object(rl, "set_texture_filter")
    mocker.patch.object(rl, "set_texture_wrap")
    mocker.patch.object(rl, "get_window_scale_dpi", return_value=rl.Vector2(1.0, 1.0))
    ground = GroundRenderer(texture=rl.Texture(), overlay=rl.Texture(), overlay_detail=rl.Texture(), width=64, height=64)
    ground.render_target = _target(ids)
    ground._render_target_ready = True
    return RenderResources(
        assets_dir=Path(), ground=ground, fx_textures=FxQueueTextures(particles=rl.Texture(), bodyset=rl.Texture()),
    )


def test_copies_of_the_terrain_spread_out_past_the_cap_and_a_rebuild_bakes_the_log_after_its_copy(
    resources: RenderResources, mocker,
) -> None:
    replay = record_replay(
        RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF), 600, inputs=player_input(aim=Vec2(700.0, 512.0), fire_down=True),
    )
    prep = ReplayPreparation(replay, background=False)
    prep.poll()
    setup = build_runtime_playback_driver(replay, max_ticks=None).terrain_setup
    mocker.patch.object(terrain_history, "SHOT_TICKS", 60)
    mocker.patch.object(terrain_history, "SHOTS", 4)
    history = TerrainHistory(resources, setup)
    history.open()

    history.feed(prep)

    # Every 60 ticks to 240, then past four copies every other one goes, and again past 480.
    assert [shot.tick for shot in history.shots] == [0, 240, 480]
    key = prep.keys[-1]
    shot = history.shots[-1]
    assert shot.bakes < key.bakes
    bake = mocker.spy(RenderResources, "bake_terrain_fx_batch")

    history.rebuild(prep, key.bakes)

    assert [call.args[1] for call in bake.call_args_list] == list(prep.bakes.read(shot.bakes, key.bakes))
    assert all(call.args[2] is resources.ground for call in bake.call_args_list)
