from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import crimson.render.world.effects as world_effects
from crimson.effects import EffectEntry
from crimson.effects_atlas import EffectId
from crimson.render.world import WorldRenderer
from crimson.render.world.context import build_world_render_ctx
from crimson.render.world.effects import draw_effect_pool
from grim.color import RGBA
from grim.geom import Vec2
from grim.raylib_api import rl


class _TextureStub:
    id = 1
    width = 256
    height = 256


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
        self.render_resources = SimpleNamespace(particles_texture=_TextureStub())
        self.sim_world = _SimWorldStub(state=_StateStub(effects=_EffectPoolStub(entries=entries)))


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
    renderer = WorldRenderer(_world=_WorldStub(entries))  # type: ignore[arg-type]
    render_ctx = build_world_render_ctx(renderer)

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
