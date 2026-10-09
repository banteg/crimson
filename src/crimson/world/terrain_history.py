"""The terrain at any tick the preparing pass reached, for the replay viewer's seeks (docs/rewrite/replay-viewer.md).

Ticks bake decals and corpses into the ground's render target, so a seek rebuilds it: from the nearest copy of the
terrain at or before the keyframe it restores, then every logged bake after the copy. The copies come from a
terrain of the history's own that bakes the pass's log as it comes in, copied as the run starts and every 30
seconds after (at most 32 copies, the spacing doubling past them).
"""

from __future__ import annotations

import msgspec

from grim.blend import opaque_blend
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.terrain_render import GroundRenderer
from grim.texture_mode import texture_mode

from ..replay.driver.prepare import ReplayPreparation
from ..sim.terrain_generate import TerrainSetup
from .render_resources import RenderResources

SHOT_TICKS = 1800
SHOTS = 32


class TerrainShot(msgspec.Struct):
    """A copy of the terrain after the first `bakes` bakes, `tick` ticks in."""

    bakes: int
    tick: int
    target: rl.RenderTexture


def _copy(target: rl.RenderTexture, source: rl.RenderTexture) -> None:
    width, height = float(source.texture.width), float(source.texture.height)
    with texture_mode(target), opaque_blend():
        # Render targets are stored upside down: a flipped source keeps the copy the same way up.
        rl.draw_texture_pro(
            source.texture,
            rl_rectangle(0.0, 0.0, width, -height),
            rl_rectangle(0.0, 0.0, width, height),
            rl_vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )


class TerrainHistory:
    def __init__(self, resources: RenderResources, setup: TerrainSetup | None) -> None:
        self._resources = resources
        self._setup = setup
        self._builder: GroundRenderer | None = None
        self._baked = 0
        self._last_key = -1
        self._spacing = SHOT_TICKS
        self.shots: list[TerrainShot] = []

    def close(self) -> None:
        for shot in self.shots:
            rl.unload_render_texture(shot.target)
        self.shots.clear()
        if self._builder is not None:
            self._builder.close()
            self._builder = None

    def open(self) -> None:
        """A terrain of its own, drawn from the run's setup as the run's ground is. Without one (a run with no setup,
        or no render targets to draw into) seeks leave the ground as it is."""
        ground = self._resources.ground
        if self._setup is None or ground is None:
            return
        builder = GroundRenderer(
            texture=ground.texture, overlay=ground.overlay, overlay_detail=ground.overlay_detail,
            width=ground.width, height=ground.height,
        )
        builder.schedule_stamps(self._setup.layers, texture_scale=self._resources.texture_scale)
        builder.process_pending()
        if builder.render_target_ready():
            self._builder = builder
        else:
            builder.close()

    def feed(self, preparation: ReplayPreparation) -> None:
        """Bakes what the pass logged since, copying the terrain at the keyframes the copies' spacing calls for."""
        builder = self._builder
        if builder is None:
            return
        for key in preparation.keys:
            if key.tick <= self._last_key:
                continue
            self._bake(builder, preparation, self._baked, key.bakes)
            self._baked = key.bakes
            self._last_key = key.tick
            if not self.shots or key.tick - self.shots[-1].tick >= self._spacing:
                self._shoot(builder, key.bakes, key.tick)

    def _bake(self, ground: GroundRenderer, preparation: ReplayPreparation, start: int, stop: int) -> None:
        for batch in preparation.bakes.read(start, stop):
            self._resources.bake_terrain_fx_batch(batch, ground)

    def _shoot(self, builder: GroundRenderer, bakes: int, tick: int) -> None:
        assert builder.render_target is not None
        texture = builder.render_target.texture
        target = rl.load_render_texture(texture.width, texture.height)
        _copy(target, builder.render_target)
        self.shots.append(TerrainShot(bakes, tick, target))
        if len(self.shots) <= SHOTS:
            return
        for shot in self.shots[1::2]:
            rl.unload_render_texture(shot.target)
        self.shots = self.shots[::2]
        self._spacing *= 2

    def rebuild(self, preparation: ReplayPreparation, bakes: int) -> None:
        """The run's ground as it stood after the first `bakes` bakes; bakes still pending are dropped."""
        self._resources.clear_pending_terrain_fx()
        # A ground not drawn yet is drawn from its setup first.
        self._resources.process_ground_pending()
        ground = self._resources.ground
        shot = next((shot for shot in reversed(self.shots) if shot.bakes <= bakes), None)
        if ground is None or ground.render_target is None or shot is None:
            return
        _copy(ground.render_target, shot.target)
        self._bake(ground, preparation, shot.bakes, bakes)
