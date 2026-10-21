from __future__ import annotations

import msgspec
import pytest

from crimson.effects import EffectEntry
from crimson.effects_atlas import EffectId
from crimson.render.rtx.gpu_smoke import GpuSmokeSimulation
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.rtx.smoke import SmokeRenderer
from crimson.render.world import effects
from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from tests.render.test_smoke_simulation import emission
from tests.support.creature_draw_capture import render_ctx_for_creatures


@pytest.mark.parametrize("failure", ["shader", "solver"])
def test_gpu_failure_restores_native_smoke_pools(failure, mocker, headless_window, headless_resources):
    smoke = SmokeRenderer()
    assert isinstance(smoke.simulation, GpuSmokeSimulation)
    smoke.consume((emission(),), dt_sim=1 / 60)
    ctx = render_ctx_for_creatures(headless_resources, [])
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(
        ctx.frame, rtx_mode=RtxRenderMode.RTX, smoke=smoke,
    ))
    shader = rl.ffi.new("Shader *")[0]
    if failure == "shader":
        shader.id = 0
        mocker.patch.object(rl, "load_shader_from_memory", return_value=shader)
    else:
        shader.id = 42
        smoke.shader = shader
        mocker.patch.object(smoke.simulation, "prepare", side_effect=RuntimeError("no float target"))
    smoke.prepare(ctx.frame, ())
    assert not smoke.available and not smoke.prepared
    assert not smoke.simulation.fields and not smoke.simulation.batches
    ctx.frame.state.sprite_effects.spawn(
        pos=Vec2(50, 50), vel=Vec2(), scale=14, color=RGBA(1, 1, 1, .25), rng=Crand(1),
    )
    ctx.frame.state.effects.entries[0] = EffectEntry(
        pos=Vec2(50, 50), effect_id=EffectId.EXPLOSION_PUFF, flags=0x40,
        scale=1., half_width=20., half_height=20., color=RGBA(1, 1, 1, 1),
    )
    effects.draw_sprite_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    effects.draw_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    assert headless_window.draw_texture_pro.call_count == 2
    smoke.consume((emission(),), dt_sim=1 / 60)
    assert not smoke.simulation.batches
