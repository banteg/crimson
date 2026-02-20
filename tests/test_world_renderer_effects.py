from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from crimson.effects import EffectEntry
from crimson.effects_atlas import EffectId
from crimson.render.world import WorldRenderer
from crimson.render.world.context import build_world_render_ctx
from crimson.render.world.effects import draw_effect_pool
from grim.color import RGBA
from grim.geom import Vec2


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


class _WorldStub:
    def __init__(self, entries: list[EffectEntry]) -> None:
        self.particles_texture = _TextureStub()
        self.state = _StateStub(effects=_EffectPoolStub(entries=entries))


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


def test_draw_effect_pool_splits_alpha_and_additive_paths(monkeypatch) -> None:
    blend_labels: list[str] = []
    current_mode: dict[str, int | None] = {"value": None}

    def _begin_blend_mode(mode: int) -> None:
        current_mode["value"] = int(mode)

    def _end_blend_mode() -> None:
        current_mode["value"] = None

    def _draw_texture_pro(*_args) -> None:
        mode = current_mode["value"]
        if mode == int(rl.BlendMode.BLEND_ALPHA):
            blend_labels.append("alpha")
        elif mode == int(rl.BlendMode.BLEND_ADDITIVE):
            blend_labels.append("additive")
        else:
            blend_labels.append("unknown")

    monkeypatch.setattr("crimson.render.world.effects.rl.begin_blend_mode", _begin_blend_mode)
    monkeypatch.setattr("crimson.render.world.effects.rl.end_blend_mode", _end_blend_mode)
    monkeypatch.setattr("crimson.render.world.effects.rl.draw_texture_pro", _draw_texture_pro)

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

    assert blend_labels == ["alpha", "additive"]

