from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, cast

import crimson.render.world.effects as world_effects
from crimson.effects import EffectEntry
from crimson.effects_atlas import EffectId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.effects import draw_effect_pool
from crimson.render.world.viewport import view_transform
from grim.assets import TextureId
from grim.color import RGBA
from grim.geom import Vec2
from grim.raylib_api import rl


class _TextureStub:
    id = 1
    width = 256
    height = 256


class _ResourcesStub:
    def texture(self, texture_id: TextureId) -> _TextureStub:
        assert texture_id == TextureId.PARTICLES
        return _TextureStub()


@dataclass(slots=True)
class _EffectPoolStub:
    entries: list[EffectEntry]


@dataclass(slots=True)
class _StateStub:
    effects: _EffectPoolStub


@dataclass(slots=True)
class _SimWorldStub:
    state: _StateStub


class _WorldStub:
    def __init__(self, entries: list[EffectEntry]) -> None:
        self.resources = _ResourcesStub()
        self.sim_world = _SimWorldStub(state=_StateStub(effects=_EffectPoolStub(entries=entries)))

    def build_render_frame(self) -> RenderFrame:
        return RenderFrame(
            world_size=1024.0,
            demo_mode_active=False,
            config=None,
            camera=Vec2(),
            ground=None,
            state=cast(Any, self.sim_world.state),
            players=[],
            creatures=cast(Any, SimpleNamespace(entries=[])),
            resources=cast(Any, self.resources),
            elapsed_ms=0.0,
            bonus_anim_phase=0.0,
            rtx_mode=RtxRenderMode.CLASSIC,
        )

def _entry(*, flags: int, pos: Vec2) -> EffectEntry:
    return EffectEntry(
        pos=pos,
        effect_id=int(EffectId.EXPLOSION_PUFF),
        rotation=0.0,
        scale=1.0,
        half_width=8.0,
        half_height=6.0,
        age=0.0,
        lifetime=1.0,
        flags=int(flags),
        color=RGBA(1.0, 1.0, 1.0, 1.0),
    )


def test_draw_effect_pool_splits_alpha_and_additive_paths(mocker) -> None:
    raylib_stub = SimpleNamespace(
        BlendMode=rl.BlendMode,
        Rectangle=rl.Rectangle,
        Vector2=rl.Vector2,
        begin_blend_mode=mocker.Mock(),
        end_blend_mode=mocker.Mock(),
        draw_texture_pro=mocker.Mock(),
    )
    mocker.patch.object(world_effects, "rl", raylib_stub)

    entries = [
        _entry(flags=0x40, pos=Vec2(10.0, 20.0)),
        _entry(flags=0x01, pos=Vec2(30.0, 40.0)),
    ]
    world = _WorldStub(entries)
    frame = world.build_render_frame()
    render_ctx = WorldRenderCtx(
        frame=frame,
        view=view_transform(
            world_size=frame.world_size, config=frame.config, camera=frame.camera, out_size=Vec2(1024, 1024),
        ),
    )

    draw_effect_pool(
        render_ctx,
        camera=Vec2(),
        view_scale=Vec2(1.0, 1.0),
        alpha=1.0,
    )

    assert raylib_stub.begin_blend_mode.call_count == 2
    assert {call.args[0] for call in raylib_stub.begin_blend_mode.call_args_list} == {
        int(rl.BlendMode.BLEND_ALPHA),
        int(rl.BlendMode.BLEND_ADDITIVE),
    }
    assert raylib_stub.end_blend_mode.call_count == 2
    assert raylib_stub.draw_texture_pro.call_count == 2
