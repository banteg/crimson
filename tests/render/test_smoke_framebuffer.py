"""Lazy smoke allocation must not detach the enclosing world render target."""
from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from crimson.render.frame import RenderFrame
from crimson.render.rtx.gpu_smoke import GpuSmokeSimulation
from crimson.render.rtx.smoke import SmokeRenderer
from crimson.render.rtx.smoke_composite import SmokeComposite
from crimson.render.world.viewport import view_transform
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.texture_mode import texture_mode


def _mark_and_check(target: rl.RenderTexture) -> None:
    # Logical coordinates are scaled by two in the enclosing texture_mode.
    rl.draw_rectangle(4, 3, 4, 3, rl.WHITE)
    rl.rl_draw_render_batch_active()
    image = rl.load_image_from_texture(target.texture)
    try:
        # Render-target readback is bottom-first.
        inside = rl.get_image_color(image, 12, 24 - 1 - 9)
        outside = rl.get_image_color(image, 20, 24 - 1 - 9)
        assert (inside.r, inside.g, inside.b) == (255, 255, 255)
        assert (outside.r, outside.g, outside.b) == (0, 0, 0)
    finally:
        rl.unload_image(image)


@pytest.mark.parametrize("failed_allocation", [None, 1, 3])
def test_native_smoke_prewarm_restores_target_on_success_and_failure(raylib_context, monkeypatch, failed_allocation):
    target = rl.load_render_texture(32, 24)
    smoke = SmokeRenderer()
    original_complete = rl.rl_framebuffer_complete
    attempts = 0

    def complete(framebuffer):
        nonlocal attempts
        attempts += 1
        result = original_complete(framebuffer)
        return result and attempts != failed_allocation

    monkeypatch.setattr(rl, "rl_framebuffer_complete", complete)
    try:
        with texture_mode(target, scale_x=2., scale_y=2.):
            rl.clear_background(rl.BLACK)
            # Prewarming has no emissions: no later solver pass can accidentally
            # repair the binding and conceal an allocation-state leak.
            frame = cast(RenderFrame, SimpleNamespace(ground=None))
            smoke.prepare(frame, ())
            assert smoke.available is (failed_allocation is None)
            if failed_allocation is not None:
                assert isinstance(smoke.simulation, GpuSmokeSimulation)
                assert not smoke.simulation.targets
                assert not smoke.simulation.fields
            _mark_and_check(target)
    finally:
        smoke.close()
        rl.unload_render_texture(target)


def test_native_smoke_composite_failure_restores_enclosing_target(raylib_context, monkeypatch):
    target = rl.load_render_texture(32, 24)
    composite = SmokeComposite()
    view = view_transform(config=None, camera=Vec2(), out_size=Vec2(16, 12))
    original_complete = rl.rl_framebuffer_complete

    def incomplete(framebuffer):
        original_complete(framebuffer)
        return False

    monkeypatch.setattr(rl, "rl_framebuffer_complete", incomplete)
    try:
        with texture_mode(target, scale_x=2., scale_y=2.):
            rl.clear_background(rl.BLACK)
            with pytest.raises(RuntimeError, match="framebuffer is incomplete"):
                composite.draw(view, lambda: None)
            assert composite.target is None
            _mark_and_check(target)
    finally:
        composite.close()
        rl.unload_render_texture(target)
