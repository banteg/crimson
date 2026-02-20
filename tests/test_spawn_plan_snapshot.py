from __future__ import annotations

from syrupy import SnapshotAssertion

from crimson.creatures.spawn import SpawnEnv, SpawnId, build_spawn_plan
from grim.geom import Vec2
from grim.rand import Crand


def _round_or_none(value: float | None) -> float | None:
    if value is None:
        return None
    return round(float(value), 6)


def _normalize_plan(template_id: int) -> dict[str, object]:
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(int(template_id), Vec2(100.0, 200.0), 0.0, Crand(0xBEEF), env)
    return {
        "template_id": int(template_id),
        "primary": int(plan.primary),
        "effects": [
            {
                "x": round(float(effect.pos.x), 6),
                "y": round(float(effect.pos.y), 6),
                "count": int(effect.count),
            }
            for effect in plan.effects
        ],
        "spawn_slots": [
            {
                "owner_creature": int(slot.owner_creature),
                "timer": round(float(slot.timer), 6),
                "count": int(slot.count),
                "limit": int(slot.limit),
                "interval": round(float(slot.interval), 6),
                "child_template_id": int(slot.child_template_id),
            }
            for slot in plan.spawn_slots
        ],
        "creatures": [
            {
                "origin_template_id": int(creature.origin_template_id),
                "pos": [round(float(creature.pos.x), 6), round(float(creature.pos.y), 6)],
                "heading": _round_or_none(creature.heading),
                "phase_seed": round(float(creature.phase_seed), 6),
                "type_id": None if creature.type_id is None else int(creature.type_id),
                "flags": int(creature.flags),
                "ai_mode": int(creature.ai_mode),
                "health": _round_or_none(creature.health),
                "max_health": _round_or_none(creature.max_health),
                "move_speed": _round_or_none(creature.move_speed),
                "reward_value": _round_or_none(creature.reward_value),
                "size": _round_or_none(creature.size),
                "contact_damage": _round_or_none(creature.contact_damage),
                "tint": None if creature.tint is None else [_round_or_none(v) for v in creature.tint],
                "orbit_angle": _round_or_none(creature.orbit_angle),
                "orbit_radius": _round_or_none(creature.orbit_radius),
                "ranged_projectile_type": creature.ranged_projectile_type,
                "ai_link_parent": creature.ai_link_parent,
                "ai_timer": creature.ai_timer,
                "target_offset": (
                    None
                    if creature.target_offset is None
                    else [round(float(creature.target_offset.x), 6), round(float(creature.target_offset.y), 6)]
                ),
                "spawn_slot": creature.spawn_slot,
                "bonus_id": None if creature.bonus_id is None else int(creature.bonus_id),
                "bonus_duration_override": creature.bonus_duration_override,
            }
            for creature in plan.creatures
        ],
    }


def test_spawn_plan_snapshot(snapshot: SnapshotAssertion) -> None:
    for template_id in (
        int(SpawnId.ALIEN_CONST_GREEN_24),
        0x03,
        0x1F,
        0x15,
    ):
        snapshot(name=f"template_{template_id:02x}").assert_match(_normalize_plan(int(template_id)))
