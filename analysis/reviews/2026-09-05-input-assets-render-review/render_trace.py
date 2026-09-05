from __future__ import annotations

import hashlib
import json
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from crimson.creatures.spawn import CreatureTypeId
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from crimson.render.world import draw as world_draw
from crimson.world.runtime import WorldRuntime
from grim.assets import RuntimeResources, TextureId
from grim.config import default_crimson_cfg
from grim.fonts.small import SmallFontData
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl


def value(v):
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (tuple, list)):
        return [value(item) for item in v]
    for fields in [("id", "width", "height"), ("r", "g", "b", "a"), ("x", "y", "width", "height"), ("x", "y")]:
        if all(hasattr(v, field) for field in fields):
            return {field: value(getattr(v, field)) for field in fields}
    raise TypeError(type(v))


results = []
for width, height in [(1024, 768), (1280, 720), (800, 600)]:
    for alpha in [1.0, 0.4, 0.0]:
        calls = []

        def record(name, calls=calls):
            def call(*args, **kwargs):
                calls.append((name, [value(v) for v in args], {k: value(v) for k, v in kwargs.items()}))

            return call

        runtime = WorldRuntime(assets_dir=Path("/tmp/assets"), config=default_crimson_cfg(), audio_rng=Crand(1))
        runtime.reset(seed=1, player_count=2)
        for i, p in enumerate(runtime.sim_world.players):
            p.pos = Vec2(240 + 100 * i, 280 + 80 * i)
            p.aim = Vec2(650, 320)
            p.health = 100 if i == 0 else 0
            p.perk_counts[int(PerkId.MONSTER_VISION)] = 1
        for i, t in enumerate(CreatureTypeId):
            c = runtime.sim_world.creatures.entries[i]
            c.active = True
            c.type_id = t
            c.pos = Vec2(220 + 60 * i, 350)
            c.size = 48
            c.hp = c.max_hp = 100
            c.lifecycle_stage = 16
        for i, t in enumerate(ProjectileTemplateId):
            p = runtime.sim_world.state.projectiles.entries[i]
            p.active = True
            p.type_id = t
            p.life_timer = 0.6
            p.pos = Vec2(250 + 20 * i, 480)
            p.origin = p.pos - Vec2(30, 15)
        for i, t in enumerate(SecondaryProjectileTypeId):
            if t == SecondaryProjectileTypeId.NONE:
                continue
            p = runtime.sim_world.state.secondary_projectiles.entries[i]
            p.active = True
            p.type_id = t
            p.pos = Vec2(400 + 20 * i, 500)
            p.vel = Vec2(10, 1)
            p.detonation_t = 0.2
        textures = {t: SimpleNamespace(id=i + 1, width=256, height=256) for i, t in enumerate(TextureId)}
        runtime.render_resources.resources = RuntimeResources(
            assets_dir=Path("/tmp/assets"),
            textures=textures,
            small_font=SmallFontData(widths=[6] * 256, texture=textures[TextureId.SMALL_WHITE]),
        )
        runtime.render_resources.ground = SimpleNamespace(draw_view=record("ground"))
        with ExitStack() as stack:
            stack.enter_context(patch.object(rl, "get_screen_width", return_value=width))
            stack.enter_context(patch.object(rl, "get_screen_height", return_value=height))
            stack.enter_context(patch.object(world_draw, "_maybe_alpha_test", side_effect=nullcontext))
            for name in dir(rl):
                if name.startswith(("draw_", "rl_")) and callable(getattr(rl, name)):
                    stack.enter_context(patch.object(rl, name, side_effect=record(name)))
            for name in ["clear_background", "begin_blend_mode", "end_blend_mode"]:
                stack.enter_context(patch.object(rl, name, side_effect=record(name)))
            runtime.update_camera()
            runtime.draw(entity_alpha=alpha)
        wire = json.dumps(calls, sort_keys=True, separators=(",", ":")).encode()
        results.append(
            {
                "width": width,
                "height": height,
                "alpha": alpha,
                "calls": len(calls),
                "sha256": hashlib.sha256(wire).hexdigest(),
            },
        )
print(json.dumps(results, indent=2))
