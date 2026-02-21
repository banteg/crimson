from __future__ import annotations

import pytest
from syrupy import SnapshotAssertion

from crimson.creatures.spawn import SPAWN_TEMPLATES, SpawnEnv, build_spawn_plan
from grim.geom import Vec2
from grim.rand import Crand

_TEMPLATE_IDS = tuple(sorted(int(entry.spawn_id) for entry in SPAWN_TEMPLATES))
_VARIANT_CASES = (
    ("demo_disabled", 0xBEEF, 0.0, {"demo_mode_active": False}, (0x00, 0x03, 0x1F)),
    ("hardcore", 0x1234, 0.0, {"hardcore": True}, (0x00, 0x15, 0x41)),
    ("alt_difficulty", 0x5555, -100.0, {"difficulty_level": 1}, (0x03, 0x04, 0x05)),
)
_VARIANT_TEMPLATE_CASES = tuple(
    pytest.param(
        case_name,
        seed,
        heading,
        env_overrides,
        int(template_id),
        id=f"{case_name}_template_{int(template_id):02x}",
    )
    for case_name, seed, heading, env_overrides, template_ids in _VARIANT_CASES
    for template_id in template_ids
)


def _round_or_none(value: float | None) -> float | None:
    if value is None:
        return None
    return round(float(value), 6)


def _normalize_plan(
    template_id: int,
    *,
    env: SpawnEnv,
    seed: int,
    heading: float,
) -> dict[str, object]:
    rng = Crand(int(seed))
    plan = build_spawn_plan(int(template_id), Vec2(100.0, 200.0), float(heading), rng, env)
    return {
        "template_id": int(template_id),
        "seed": int(seed),
        "heading": round(float(heading), 6),
        "rng_state": int(rng.state),
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
                "type_id": None if creature.type_id is None else int(creature.type_id),
                "pos": [round(float(creature.pos.x), 6), round(float(creature.pos.y), 6)],
                "heading": _round_or_none(creature.heading),
                "phase_seed": round(float(creature.phase_seed), 6),
                "flags": int(creature.flags),
                "ai_mode": int(creature.ai_mode),
                "health": _round_or_none(creature.health),
                "max_health": _round_or_none(creature.max_health),
                "move_speed": _round_or_none(creature.move_speed),
                "reward_value": _round_or_none(creature.reward_value),
                "size": _round_or_none(creature.size),
                "contact_damage": _round_or_none(creature.contact_damage),
                "tint": None if creature.tint is None else [_round_or_none(component) for component in creature.tint],
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


@pytest.mark.parametrize(
    "template_id",
    [pytest.param(int(template_id), id=f"default_template_{int(template_id):02x}") for template_id in _TEMPLATE_IDS],
)
def test_spawn_plan_templates_snapshot(
    snapshot: SnapshotAssertion,
    default_spawn_env: SpawnEnv,
    template_id: int,
) -> None:
    snapshot(name=f"default_template_{template_id:02x}").assert_match(
        _normalize_plan(
            int(template_id),
            env=default_spawn_env,
            seed=0xBEEF,
            heading=0.0,
        ),
    )


@pytest.mark.parametrize(
    ("case_name", "seed", "heading", "env_overrides", "template_id"),
    _VARIANT_TEMPLATE_CASES,
)
def test_spawn_plan_variant_snapshot(
    snapshot: SnapshotAssertion,
    make_spawn_env,
    case_name: str,
    seed: int,
    heading: float,
    env_overrides: dict[str, object],
    template_id: int,
) -> None:
    env = make_spawn_env(**env_overrides)
    snapshot(name=f"{case_name}_template_{template_id:02x}").assert_match(
        _normalize_plan(
            int(template_id),
            env=env,
            seed=int(seed),
            heading=float(heading),
        ),
    )


def test_spawn_plan_seed_stability(default_spawn_env: SpawnEnv) -> None:
    baseline = _normalize_plan(0x1F, env=default_spawn_env, seed=0xBEEF, heading=0.0)
    repeat = _normalize_plan(0x1F, env=default_spawn_env, seed=0xBEEF, heading=0.0)
    changed_seed = _normalize_plan(0x1F, env=default_spawn_env, seed=0xBEEE, heading=0.0)

    assert baseline == repeat
    assert baseline != changed_seed
