from __future__ import annotations

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
from crimson.sim.gameplay_state import GameplayState
from grim.assets import RuntimeResources, TextureId
from grim.color import RGBA
from grim.geom import Vec2
from grim.raylib_api import rl


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


def test_draw_effect_pool_splits_alpha_and_additive_paths(mocker, headless_resources: RuntimeResources) -> None:
    raylib_stub = SimpleNamespace(
        BlendMode=rl.BlendMode,
        Rectangle=rl.Rectangle,
        Vector2=rl.Vector2,
        begin_blend_mode=mocker.Mock(),
        end_blend_mode=mocker.Mock(),
        draw_texture_pro=mocker.Mock(),
    )
    mocker.patch.object(world_effects, "rl", raylib_stub)
    texture = mocker.spy(RuntimeResources, "texture")

    state = GameplayState()
    state.effects.entries[0] = _entry(flags=0x40, pos=Vec2(10.0, 20.0))
    state.effects.entries[1] = _entry(flags=0x01, pos=Vec2(30.0, 40.0))
    frame = RenderFrame(
        config=None,
        camera=Vec2(),
        ground=None,
        state=state,
        players=[],
        creatures=cast(Any, SimpleNamespace(entries=[])),
        resources=headless_resources,
        elapsed_ms=0.0,
        bonus_anim_phase=0.0,
        rtx_mode=RtxRenderMode.CLASSIC,
    )
    render_ctx = WorldRenderCtx(
        frame=frame,
        view=view_transform(
            config=frame.config, camera=frame.camera, out_size=Vec2(1024, 1024),
        ),
    )

    draw_effect_pool(
        render_ctx,
        camera=Vec2(),
        view_scale=Vec2(1.0, 1.0),
    )

    assert [call.args[1] for call in texture.call_args_list] == [TextureId.PARTICLES]
    assert raylib_stub.begin_blend_mode.call_count == 2
    assert {call.args[0] for call in raylib_stub.begin_blend_mode.call_args_list} == {
        int(rl.BlendMode.BLEND_ALPHA),
        int(rl.BlendMode.BLEND_ADDITIVE),
    }
    assert raylib_stub.end_blend_mode.call_count == 2
    assert raylib_stub.draw_texture_pro.call_count == 2
