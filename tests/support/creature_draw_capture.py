"""Capture production creature draw order at the Raylib call boundary."""

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import msgspec

from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.render.world import draw as world_draw
from grim.color import RGBA
from grim.config import default_crimson_cfg
from grim.geom import Vec2
from tests.render.test_world_draw_order import _render_ctx_for_creatures, _TextureStub
from tests.support.factories import make_creature_state


def capture_creature_draws(case, *, module=world_draw, texture_size=512):
    creatures = []
    indices = {}
    for row in case["creatures"]:
        creature = make_creature_state(
            pos=Vec2(row["pos_x"], row["pos_y"]),
            active=bool(row["active"]),
            type_id=CreatureTypeId(row["type_id"]),
            lifecycle_stage=row["lifecycle_stage"],
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
    render_ctx = _render_ctx_for_creatures(creatures)
    render_ctx.frame.state.bonuses.energizer = case["energizer"]
    render_ctx = msgspec.structs.replace(
        render_ctx,
        frame=msgspec.structs.replace(render_ctx.frame, config=config, players=cast(Any, [SimpleNamespace()])),
    )
    additive = False
    active_index = None
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
        nonlocal active_index, active_type
        active_index = indices[kwargs["pos"]]
        active_type = int(kwargs["type_id"])
        return sprite(*args, **kwargs)

    def draw_texture(_texture, src, dst, _origin, _rotation, tint):
        assert active_index is not None
        cell = texture_size / 8
        drawn.append(
            {
                "index": active_index,
                "type_id": active_type,
                "pass": "flash" if additive else "shadow" if (tint.r, tint.g, tint.b) == (0, 0, 0) else "body",
                "frame": int(src.x / cell) + int(src.y / cell) * 8,
                "width": dst.width,
                "height": dst.height,
            },
        )

    with (
        patch.object(module, "draw_creature_overlays"),
        patch.object(module, "perk_active", return_value=bool(case["monster_vision"])),
        patch.object(module, "_creature_texture", return_value=_TextureStub(texture_size, texture_size)),
        patch.object(module, "draw_creature_sprite", side_effect=draw_sprite),
        patch.object(module.rl, "draw_texture_pro", side_effect=draw_texture),
        patch.object(module.rl, "begin_blend_mode", side_effect=begin),
        patch.object(module.rl, "end_blend_mode", side_effect=end),
    ):
        module.draw_creatures(render_ctx, ctx=module.WorldDrawContext(entity_alpha=case["transition"]))
    assert not additive
    return drawn
