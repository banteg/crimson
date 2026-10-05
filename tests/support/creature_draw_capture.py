"""Capture production creature draw order at the Raylib call boundary."""

from collections.abc import Sequence
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import msgspec

from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.perks import PerkId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import draw as world_draw
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.viewport import view_transform
from crimson.sim.gameplay_state import GameplayState
from grim.assets import RuntimeResources
from grim.color import RGBA
from grim.config import default_crimson_cfg
from grim.geom import Vec2
from tests.support.factories import make_creature_state


def render_ctx_for_creatures(resources: RuntimeResources, creatures: Sequence[object]) -> WorldRenderCtx:
    frame = RenderFrame(
        config=None,
        camera=Vec2(),
        ground=None,
        state=GameplayState(),
        players=[],
        creatures=cast(Any, SimpleNamespace(entries=creatures)),
        resources=resources,
        elapsed_ms=0.0,
        bonus_anim_phase=0.0,
        rtx_mode=RtxRenderMode.CLASSIC,
    )
    return WorldRenderCtx(
        frame=frame,
        view=view_transform(config=frame.config, camera=frame.camera, out_size=Vec2(1024, 1024)),
    )


@dataclass(slots=True)
class _AtlasSize:
    """A creature atlas of another size: the shipped atlases are all 512px, and the
    native frame and quad arithmetic is also checked against 256px ones."""

    width: int
    height: int


def capture_creature_draws(case, resources: RuntimeResources, *, module=world_draw, texture_size=512, include_color=False):
    creatures = []
    indices = {}
    for row in case["creatures"]:
        creature = make_creature_state(
            pos=Vec2(row["pos_x"], row["pos_y"]),
            active=bool(row["active"]),
            type_id=CreatureTypeId(row["type_id"]),
            death_timer=row["death_timer"],
            size=row["size"],
            flags=CreatureFlags(row["flags"]),
            max_hp=row["max_health"],
        )
        creature.anim_phase = row["anim_phase"]
        creature.heading = row["heading"]
        creature.hit_flash_timer = row["hit_flash_timer"]
        creature.tint = RGBA(*(row[f"tint_{axis}"] for axis in "rgba"))
        creatures.append(creature)
        indices[creature.pos] = row["index"]
    config = default_crimson_cfg()
    config.display.violence_disabled = case["flash"]
    config.display.shadows_enabled = case["shadows"]
    render_ctx = render_ctx_for_creatures(resources, creatures)
    render_ctx.frame.state.bonuses.energizer = case["energizer"]
    render_ctx.frame.state.perks[PerkId.MONSTER_VISION] = int(case["monster_vision"])
    render_ctx = msgspec.structs.replace(
        render_ctx,
        frame=msgspec.structs.replace(render_ctx.frame, config=config, players=cast(Any, [SimpleNamespace()])),
    )
    additive = False
    active_index = None
    shadow_pending = False
    active_type = None
    drawn = []
    sprite = module.draw_creature_sprite

    def begin(mode):
        nonlocal additive
        assert not additive and mode == module.rl.BlendMode.BLEND_ADDITIVE
        additive = True

    def end():
        nonlocal additive
        assert additive
        additive = False

    def draw_sprite(*args, **kwargs):
        nonlocal active_index, active_type, shadow_pending
        shadow_pending = kwargs.get("shadow", False)
        active_index = indices[kwargs["pos"]]
        active_type = int(kwargs["type_id"])
        return sprite(*args, **kwargs)

    def draw_texture(_texture, src, dst, _origin, _rotation, tint):
        nonlocal shadow_pending
        assert active_index is not None
        cell = texture_size / 8
        drawn.append(
            {
                "index": active_index,
                "type_id": active_type,
                "pass": "flash" if additive else "shadow" if shadow_pending else "body",
                "frame": int(src.x / cell) + int(src.y / cell) * 8,
                "width": dst.width,
                "height": dst.height,
            },
        )
        if include_color:
            drawn[-1]["rgba"] = [tint.r, tint.g, tint.b, tint.a]
        shadow_pending = False

    with (
        patch.object(module, "draw_creature_overlays"),
        patch.object(module, "_creature_texture", return_value=_AtlasSize(texture_size, texture_size)),
        patch.object(module, "draw_creature_sprite", side_effect=draw_sprite),
        patch.object(module.rl, "draw_texture_pro", side_effect=draw_texture),
        patch.object(module.rl, "begin_blend_mode", side_effect=begin),
        patch.object(module.rl, "end_blend_mode", side_effect=end),
    ):
        module.draw_creatures(render_ctx, ctx=module.WorldDrawContext(entity_alpha=case["transition"]))
    assert not additive
    return drawn
