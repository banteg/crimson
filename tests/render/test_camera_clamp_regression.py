from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

import pytest

from crimson.render.world import renderer as world_renderer
from crimson.world import runtime as world_runtime
from grim import terrain_render
from grim.config import CrimsonConfig, default_crimson_cfg
from grim.geom import Vec2
from grim.terrain_render import GroundCorpseDecal, GroundDecal, GroundRenderer
from tests.support.helpers import assert_float_close
from tests.support.world_runtime import WorldRuntimeHost

if TYPE_CHECKING:
    from grim.raylib_api import rl


class _TextureLike(Protocol):
    id: int
    width: int
    height: int


class _RenderTextureLike(Protocol):
    id: int
    texture: _TextureLike


@dataclass(slots=True)
class _TextureStub(_TextureLike):
    id: int = 1
    width: int = 16
    height: int = 16


@dataclass(slots=True)
class _RenderTextureStub(_RenderTextureLike):
    id: int = 1
    texture: _TextureStub = field(default_factory=lambda: _TextureStub(id=2, width=1024, height=1024))


def _as_texture(texture: _TextureLike) -> rl.Texture:
    return cast("rl.Texture", texture)


def _as_render_texture(render_target: _RenderTextureLike) -> rl.RenderTexture:
    return cast("rl.RenderTexture", render_target)


def _ground(
    *,
    texture: _TextureLike | None = None,
    overlay: _TextureLike | None = None,
    detail: _TextureLike | None = None,
    width: int = 1024,
    height: int = 1024,
    texture_scale: float = 1.0,
) -> GroundRenderer:
    base = _TextureStub() if texture is None else texture
    overlay_tex = base if overlay is None else overlay
    detail_tex = base if detail is None else detail
    return GroundRenderer(
        texture=_as_texture(base),
        overlay=_as_texture(overlay_tex),
        overlay_detail=_as_texture(detail_tex),
        width=width,
        height=height,
        texture_scale=texture_scale,
    )


def _runtime_world(
    *,
    world_size: float = 1024.0,
    screen_width: int | None = None,
    screen_height: int | None = None,
) -> WorldRuntimeHost:
    repo_root = Path(__file__).resolve().parents[1]
    cfg: CrimsonConfig | None = None
    if screen_width is not None and screen_height is not None:
        cfg = default_crimson_cfg(repo_root / "artifacts" / "tmp_crimson.cfg")
        cfg.display.width = int(screen_width)
        cfg.display.height = int(screen_height)
    return WorldRuntimeHost(
        assets_dir=repo_root / "artifacts" / "assets",
        world_size=float(world_size),
        config=cfg,
    )


def test_ground_clamp_is_stable_when_screen_matches_world_width() -> None:
    texture = _TextureStub()
    ground = _ground(texture=texture)
    clamped = ground._clamp_camera(Vec2(-0.25, -5.0), 1024.0, 768.0)
    assert clamped.x == 0.0


def test_world_clamp_is_stable_when_screen_matches_world_width() -> None:
    renderer = _runtime_world(world_size=1024.0).renderer
    clamped = renderer._clamp_camera(Vec2(-0.25, -5.0), Vec2(1024.0, 768.0))
    assert clamped.x == 0.0


def test_world_camera_screen_size_fits_widescreen_uniformly() -> None:
    renderer = _runtime_world(
        world_size=1024.0,
        screen_width=1280,
        screen_height=720,
    ).renderer
    size = renderer._camera_screen_size(runtime_w=0.0, runtime_h=0.0)
    assert_float_close(size.x, 1024.0)
    assert_float_close(size.y, 576.0)


def test_world_camera_screen_size_prefers_runtime_dimensions_over_stale_config(mocker) -> None:
    renderer = _runtime_world(
        world_size=1024.0,
        screen_width=1024,
        screen_height=768,
    ).renderer
    mocker.patch.object(world_renderer.rl, "get_screen_width", return_value=1280)
    mocker.patch.object(world_renderer.rl, "get_screen_height", return_value=720)
    size = renderer._camera_screen_size()
    assert_float_close(size.x, 1024.0)
    assert_float_close(size.y, 576.0)


def test_world_camera_screen_size_uses_frame_snapshot_when_provided(mocker) -> None:
    renderer = _runtime_world(
        world_size=1024.0,
        screen_width=1024,
        screen_height=768,
    ).renderer
    mocker.patch.object(world_renderer.rl, "get_screen_width", return_value=1024)
    mocker.patch.object(world_renderer.rl, "get_screen_height", return_value=768)
    size = renderer._camera_screen_size(runtime_w=1280.0, runtime_h=720.0)
    assert_float_close(size.x, 1024.0)
    assert_float_close(size.y, 576.0)


def test_runtime_update_camera_uses_viewport_math_without_renderer_helpers(mocker) -> None:
    world = _runtime_world(
        world_size=1024.0,
        screen_width=1024,
        screen_height=768,
    )
    player = world.sim_world.players[0]
    player.health = 100.0
    player.pos = Vec2(512.0, 512.0)
    mocker.patch.object(world_runtime.rl, "get_screen_width", return_value=1280)
    mocker.patch.object(world_runtime.rl, "get_screen_height", return_value=720)
    mocker.patch.object(world_renderer.WorldRenderer, "_camera_screen_size", side_effect=AssertionError("unused"))
    mocker.patch.object(world_renderer.WorldRenderer, "_clamp_camera", side_effect=AssertionError("unused"))

    world.update_camera(0.0)

    assert_float_close(world.camera.x, 0.0)
    assert_float_close(world.camera.y, -224.0)


def test_renderer_viewport_helpers_are_frame_independent(mocker) -> None:
    renderer = world_renderer.WorldRenderer(
        world_size=1024.0,
        config=None,
        camera=Vec2(-32.0, -48.0),
    )
    mocker.patch.object(world_renderer.rl, "get_screen_width", return_value=1280)
    mocker.patch.object(world_renderer.rl, "get_screen_height", return_value=720)

    screen_size = renderer._camera_screen_size()
    assert_float_close(screen_size.x, 1024.0)
    assert_float_close(screen_size.y, 576.0)

    camera, view_scale = renderer._world_params()
    assert_float_close(camera.x, 0.0)
    assert_float_close(camera.y, -48.0)
    assert_float_close(view_scale.x, 1.25)
    assert_float_close(view_scale.y, 1.25)

    screen = renderer.world_to_screen(Vec2(100.0, 200.0))
    assert_float_close(screen.x, 125.0)
    assert_float_close(screen.y, 190.0)

    world = renderer.screen_to_world(screen)
    assert_float_close(world.x, 100.0)
    assert_float_close(world.y, 200.0)


def test_runtime_build_render_frame_requires_bound_resources() -> None:
    world = _runtime_world(world_size=1024.0)

    with pytest.raises(AssertionError, match="runtime resources must be loaded before use"):
        world.build_render_frame()


def test_ground_draw_view_uses_explicit_output_dimensions_without_refitting(mocker) -> None:
    texture = _TextureStub()
    ground = _ground(texture=texture)
    ground.render_target = _as_render_texture(_RenderTextureStub())
    ground._render_target_ready = True

    @contextmanager
    def _noop_blend(*_args, **_kwargs):
        yield

    mocker.patch.object(terrain_render.rl, "get_screen_width", return_value=1024)
    mocker.patch.object(terrain_render.rl, "get_screen_height", return_value=768)
    mocker.patch.object(terrain_render, "_blend_custom", side_effect=_noop_blend)
    fit_view_window = mocker.patch.object(
        terrain_render.GroundRenderer,
        "_fit_view_window",
        autospec=True,
        side_effect=AssertionError("unused"),
    )
    clamp_camera = mocker.patch.object(
        terrain_render.GroundRenderer,
        "_clamp_camera",
        autospec=True,
        side_effect=AssertionError("unused"),
    )
    draw_texture_pro = mocker.patch.object(
        terrain_render.rl,
        "draw_texture_pro",
        autospec=True,
    )

    ground.draw_view(
        Vec2(-1.0, -1.0),
        screen_w=1024.0,
        screen_h=576.0,
        out_w=1280.0,
        out_h=720.0,
    )

    calls = [(float(call.args[2].width), float(call.args[2].height)) for call in draw_texture_pro.call_args_list]
    assert calls == [(1280.0, 720.0)]
    fit_view_window.assert_not_called()
    clamp_camera.assert_not_called()


def test_ground_draw_uses_runtime_dimensions_when_screen_size_is_omitted(mocker) -> None:
    texture = _TextureStub()
    ground = _ground(texture=texture)
    ground.render_target = _as_render_texture(_RenderTextureStub())
    ground._render_target_ready = True

    @contextmanager
    def _noop_blend(*_args, **_kwargs):
        yield

    mocker.patch.object(terrain_render.rl, "get_screen_width", return_value=1280)
    mocker.patch.object(terrain_render.rl, "get_screen_height", return_value=720)
    mocker.patch.object(terrain_render, "_blend_custom", side_effect=_noop_blend)
    mocker.patch.object(terrain_render.rl, "draw_texture_pro", side_effect=lambda *_args, **_kwargs: None)
    fit_view_window = mocker.patch.object(
        terrain_render.GroundRenderer,
        "_fit_view_window",
        autospec=True,
        return_value=(1024.0, 576.0),
    )

    ground.draw(Vec2(-1.0, -1.0))

    fit_inputs = [(float(call.args[1]), float(call.args[2])) for call in fit_view_window.call_args_list]
    assert fit_inputs == [(1280.0, 720.0)]


def test_scheduled_generation_uses_overlay_detail_for_third_pass(mocker) -> None:
    base = _TextureStub(id=1)
    overlay = _TextureStub(id=2)
    detail = _TextureStub(id=3)
    ground = _ground(texture=base, overlay=overlay, detail=detail)
    ground.render_target = _as_render_texture(_RenderTextureStub())

    rt_scatter = mocker.patch.object(
        terrain_render.GroundRenderer,
        "_scatter_texture",
        autospec=True,
    )
    mocker.patch.object(terrain_render.GroundRenderer, "_ensure_render_target", autospec=True, side_effect=lambda _self: None)
    mocker.patch.object(terrain_render.rl, "begin_texture_mode", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(terrain_render.rl, "clear_background", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(terrain_render.rl, "end_texture_mode", side_effect=lambda *_args, **_kwargs: None)

    @contextmanager
    def _noop_blend(*_args, **_kwargs):
        yield

    mocker.patch.object(terrain_render, "_terrain_rt_blend", side_effect=_noop_blend)
    alpha_test = mocker.patch.object(terrain_render, "_maybe_alpha_test", side_effect=_noop_blend)

    ground.schedule_generate(seed=1337)
    ground.process_pending()

    assert [call.args[1] for call in rt_scatter.call_args_list] == [base, overlay, detail]
    alpha_test.assert_called_once_with()


def test_terrain_rt_blend_mask_alpha_writes_uses_color_mask(mocker) -> None:
    events: list[str] = []

    @contextmanager
    def _record(name: str):
        events.append(f"{name}:enter")
        yield
        events.append(f"{name}:exit")

    blend_custom = mocker.patch.object(
        terrain_render,
        "_blend_custom",
        side_effect=lambda *_args, **_kwargs: _record("blend"),
    )
    color_mask = mocker.patch.object(terrain_render.rl, "rl_color_mask", autospec=True)

    with terrain_render._terrain_rt_blend(1, 2, 3):
        events.append("body")

    assert events == ["blend:enter", "body", "blend:exit"]
    blend_custom.assert_called_once_with(1, 2, 3)
    assert [call.args for call in color_mask.call_args_list] == [
        (True, True, True, False),
        (True, True, True, True),
    ]


def test_alpha_test_shader_failure_raises(mocker) -> None:
    mocker.patch.object(terrain_render.rl, "load_shader_from_memory", side_effect=RuntimeError("compile failed"))
    terrain_render._get_alpha_test_shader.cache_clear()

    with pytest.raises(RuntimeError, match="compile failed"), terrain_render._maybe_alpha_test():
        pass


def test_create_render_target_recovers_after_previous_failure(mocker) -> None:
    ground = _ground()
    attempts = iter([False, True])

    mocker.patch.object(
        terrain_render.GroundRenderer,
        "_render_target_size_for",
        autospec=True,
        return_value=(1024, 1024),
    )

    def _ensure(self: GroundRenderer, _render_w: int, _render_h: int) -> bool:
        ok = next(attempts)
        if ok:
            self.render_target = _as_render_texture(_RenderTextureStub())
        return ok

    mocker.patch.object(
        terrain_render.GroundRenderer,
        "_load_render_target",
        autospec=True,
        side_effect=_ensure,
    )

    ground._ensure_render_target()
    assert ground.texture_failed is True

    ground._ensure_render_target()
    assert ground.texture_failed is False
    assert ground.render_target is not None


def test_load_render_target_rejects_incomplete_framebuffer(mocker) -> None:
    ground = _ground()
    candidate = _as_render_texture(_RenderTextureStub())
    unload_render_texture = mocker.patch.object(terrain_render.rl, "unload_render_texture", autospec=True)
    mocker.patch.object(terrain_render.rl, "load_render_texture", autospec=True, return_value=candidate)
    mocker.patch.object(terrain_render.rl, "rl_framebuffer_complete", autospec=True, return_value=False)

    assert ground._load_render_target(1024, 1024) is False
    unload_render_texture.assert_called_once_with(candidate)


def test_process_pending_clears_failed_schedule_after_terminal_rt_failure(mocker) -> None:
    ground = _ground()
    mocker.patch.object(
        terrain_render.GroundRenderer,
        "_render_target_size_for",
        autospec=True,
        return_value=(1024, 1024),
    )
    mocker.patch.object(
        terrain_render.GroundRenderer,
        "_load_render_target",
        autospec=True,
        return_value=False,
    )

    ground.schedule_generate(seed=1337)
    ground.process_pending()

    assert ground.texture_failed is True
    assert ground.generation_pending() is False


def test_ground_renderer_requires_all_three_textures() -> None:
    ground_renderer_ctor = cast(Any, GroundRenderer)
    with pytest.raises(TypeError):
        ground_renderer_ctor(
            texture=_as_texture(_TextureStub(id=1)),
            overlay=_as_texture(_TextureStub(id=2)),
        )


def test_bake_decals_returns_false_without_render_target(mocker) -> None:
    ground = _ground()
    decal = GroundDecal(
        texture=_as_texture(_TextureStub(id=2)),
        src=terrain_render.rl.Rectangle(0.0, 0.0, 16.0, 16.0),
        pos=Vec2(10.0, 10.0),
        width=16.0,
        height=16.0,
    )

    assert ground.bake_decals((decal,)) is False


def test_bake_decals_keep_default_filter(mocker) -> None:
    decal_texture = _as_texture(_TextureStub(id=2))
    ground = _ground(texture=_TextureStub(id=1))
    ground.render_target = _as_render_texture(_RenderTextureStub())
    ground._render_target_ready = True
    decal = GroundDecal(
        texture=decal_texture,
        src=terrain_render.rl.Rectangle(0.0, 0.0, 16.0, 16.0),
        pos=Vec2(10.0, 10.0),
        width=16.0,
        height=16.0,
    )

    mocker.patch.object(terrain_render.rl, "begin_texture_mode", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(terrain_render.rl, "end_texture_mode", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(terrain_render.rl, "draw_texture_pro", side_effect=lambda *_args, **_kwargs: None)
    set_texture_filter = mocker.patch.object(terrain_render.rl, "set_texture_filter", autospec=True)

    @contextmanager
    def _noop_blend(*_args, **_kwargs):
        yield

    alpha_test = mocker.patch.object(terrain_render, "_maybe_alpha_test", side_effect=_noop_blend)
    mocker.patch.object(terrain_render, "_terrain_rt_blend", side_effect=_noop_blend)

    assert ground.bake_decals((decal,)) is True

    alpha_test.assert_called_once_with()
    set_texture_filter.assert_not_called()


def test_bake_corpse_decals_keeps_default_filter(mocker) -> None:
    bodyset_texture = _as_texture(_TextureStub(id=9, width=64, height=64))
    ground = _ground(texture=_TextureStub(id=1))
    ground.render_target = _as_render_texture(_RenderTextureStub())
    ground._render_target_ready = True
    decal = GroundCorpseDecal(
        bodyset_frame=3,
        top_left=Vec2(20.0, 30.0),
        size=32.0,
        rotation_rad=0.5,
    )

    mocker.patch.object(terrain_render.rl, "begin_texture_mode", side_effect=lambda *_args, **_kwargs: None)
    mocker.patch.object(terrain_render.rl, "end_texture_mode", side_effect=lambda *_args, **_kwargs: None)
    set_texture_filter = mocker.patch.object(terrain_render.rl, "set_texture_filter", autospec=True)
    draw_shadow_pass = mocker.patch.object(
        terrain_render.GroundRenderer,
        "_draw_corpse_shadow_pass",
        autospec=True,
        side_effect=lambda *_args, **_kwargs: None,
    )
    draw_color_pass = mocker.patch.object(
        terrain_render.GroundRenderer,
        "_draw_corpse_color_pass",
        autospec=True,
        side_effect=lambda *_args, **_kwargs: None,
    )

    @contextmanager
    def _noop_alpha(*_args, **_kwargs):
        yield

    mocker.patch.object(terrain_render, "_maybe_alpha_test", side_effect=_noop_alpha)

    assert ground.bake_corpse_decals(bodyset_texture, (decal,)) is True

    set_texture_filter.assert_not_called()
    draw_shadow_pass.assert_called_once()
    draw_color_pass.assert_called_once()


def test_ground_draw_without_render_target_clears_background(mocker) -> None:
    ground = _ground()
    draw_rectangle = mocker.patch.object(terrain_render.rl, "draw_rectangle", autospec=True)
    draw_texture_pro = mocker.patch.object(terrain_render.rl, "draw_texture_pro", autospec=True)

    ground.draw_view(
        Vec2(-1.0, -1.0),
        screen_w=1024.0,
        screen_h=576.0,
        out_w=1280.0,
        out_h=720.0,
    )

    draw_rectangle.assert_called_once()
    draw_texture_pro.assert_not_called()
