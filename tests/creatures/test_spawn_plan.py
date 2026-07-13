from __future__ import annotations

import pytest
from syrupy import SnapshotAssertion

from crimson.creatures.spawn import (
    RANDOM_HEADING_SENTINEL,
    SPAWN_TEMPLATES,
    SpawnEnv,
    SpawnId,
    UnsupportedSpawnTemplateError,
    build_spawn_plan,
)
from crimson.rng_caller_static import RngCallerStatic
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.helpers import ScriptedCrand

_TEMPLATE_IDS = tuple(sorted(entry.spawn_id for entry in SPAWN_TEMPLATES))
_VARIANT_CASES = (
    (
        "demo_disabled",
        0xBEEF,
        0.0,
        {"demo_mode_active": False},
        (SpawnId.ZOMBIE_BOSS_SPAWNER_00, SpawnId.SPIDER_SP1_RANDOM_03, SpawnId.ALIEN_RANDOM_1F),
    ),
    (
        "hardcore",
        0x1234,
        0.0,
        {"hardcore": True},
        (SpawnId.ZOMBIE_BOSS_SPAWNER_00, SpawnId.FORMATION_GRID_ALIEN_WHITE_15, SpawnId.ZOMBIE_RANDOM_41),
    ),
    (
        "alt_retry_count",
        0x5555,
        -100.0,
        {"quest_fail_retry_count": 1},
        (SpawnId.SPIDER_SP1_RANDOM_03, SpawnId.LIZARD_RANDOM_04, SpawnId.SPIDER_SP2_RANDOM_05),
    ),
)
_VARIANT_TEMPLATE_CASES = tuple(
    pytest.param(
        case_name,
        seed,
        heading,
        env_overrides,
        template_id,
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
    template_id: SpawnId,
    *,
    env: SpawnEnv,
    seed: int,
    heading: float,
) -> dict[str, object]:
    rng = Crand(int(seed))
    plan = build_spawn_plan(template_id, Vec2(100.0, 200.0), float(heading), rng, env)
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
                "phase_seed": int(creature.phase_seed),
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
    [pytest.param(template_id, id=f"default_template_{int(template_id):02x}") for template_id in _TEMPLATE_IDS],
)
def test_spawn_plan_templates_snapshot(
    snapshot: SnapshotAssertion,
    default_spawn_env: SpawnEnv,
    template_id: SpawnId,
) -> None:
    snapshot(name=f"default_template_{template_id:02x}").assert_match(
        _normalize_plan(
            template_id,
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
    template_id: SpawnId,
) -> None:
    env = make_spawn_env(**env_overrides)
    snapshot(name=f"{case_name}_template_{template_id:02x}").assert_match(
        _normalize_plan(
            template_id,
            env=env,
            seed=int(seed),
            heading=float(heading),
        ),
    )


def test_spawn_plan_seed_stability(default_spawn_env: SpawnEnv) -> None:
    baseline = _normalize_plan(SpawnId.ALIEN_RANDOM_1F, env=default_spawn_env, seed=0xBEEF, heading=0.0)
    repeat = _normalize_plan(SpawnId.ALIEN_RANDOM_1F, env=default_spawn_env, seed=0xBEEF, heading=0.0)
    changed_seed = _normalize_plan(SpawnId.ALIEN_RANDOM_1F, env=default_spawn_env, seed=0xBEEE, heading=0.0)

    assert baseline == repeat
    assert baseline != changed_seed


def test_ring_formation_uses_native_angle_stores_and_fallthrough(default_spawn_env: SpawnEnv) -> None:
    plan = build_spawn_plan(
        SpawnId.FORMATION_RING_ALIEN_8_12,
        Vec2(100.0, 200.0),
        0.0,
        Crand(0xBEEF),
        default_spawn_env,
    )

    assert plan.creatures[3].target_offset == Vec2(-4.371138857095502e-06, 100.0)
    assert plan.creatures[6].target_offset == Vec2(-70.71066284179688, -70.710693359375)
    assert plan.creatures[-1].health == 20.0


def test_build_spawn_plan_rejects_unsupported_template_id(default_spawn_env: SpawnEnv) -> None:
    with pytest.raises(UnsupportedSpawnTemplateError, match=r"unsupported spawn template id: 0x2"):
        build_spawn_plan(SpawnId.UNUSED_02, Vec2(100.0, 200.0), 0.0, Crand(0xBEEF), default_spawn_env)


@pytest.mark.parametrize(
    ("template_id", "caller"),
    [
        (SpawnId.AI1_ALIEN_BLUE_TINT_1A, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI1_BLUE_TINT_1A),
        (SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI1_BLUE_TINT_1B),
        (SpawnId.AI1_LIZARD_BLUE_TINT_1C, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI1_BLUE_TINT_1C),
    ],
)
def test_build_spawn_plan_ai1_blue_tint_uses_exact_native_callers(
    default_spawn_env: SpawnEnv,
    template_id: SpawnId,
    caller: RngCallerStatic,
) -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    build_spawn_plan(template_id, Vec2(100.0, 200.0), RANDOM_HEADING_SENTINEL, rng, default_spawn_env)

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_RANDOM_HEADING,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
        caller,
    ]


@pytest.mark.parametrize(
    ("template_id", "callers"),
    [
        (
            SpawnId.ALIEN_AI7_ORBITER_36,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI7_ORBITER_TINT_G,
            ],
        ),
        (
            SpawnId.SPIDER_SP2_RANGED_VARIANT_37,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANGED_VARIANT_37_SIZE,
            ],
        ),
        (
            SpawnId.SPIDER_SP1_AI7_TIMER_38,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_AI7_TIMER_38_SIZE,
            ],
        ),
        (
            SpawnId.SPIDER_SP1_AI7_TIMER_WEAK_39,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_AI7_TIMER_WEAK_39_SIZE,
            ],
        ),
        (
            SpawnId.SPIDER_SP1_RANDOM_3D,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_3D_TINT,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_3D_SIZE,
            ],
        ),
    ],
)
def test_build_spawn_plan_direct_template_rand_sites_use_exact_native_callers(
    default_spawn_env: SpawnEnv,
    template_id: SpawnId,
    callers: list[RngCallerStatic],
) -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    build_spawn_plan(template_id, Vec2(100.0, 200.0), 0.0, rng, default_spawn_env)

    assert [record.caller for record in rng.records_since()] == callers


@pytest.mark.parametrize(
    ("template_id", "callers"),
    [
        (
            SpawnId.SPIDER_SP1_RANDOM_03,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.LIZARD_RANDOM_04,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_04_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_04_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_04_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.SPIDER_SP2_RANDOM_05,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ALIEN_RANDOM_06,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ALIEN_RANDOM_1D,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_REWARD,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_R,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ALIEN_RANDOM_1E,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_REWARD,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_TINT_R,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ALIEN_RANDOM_1F,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_REWARD,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_TINT_R,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ALIEN_RANDOM_GREEN_20,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.LIZARD_RANDOM_2E,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_TINT_R,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.LIZARD_RANDOM_31,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_31_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_31_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_31_TINT,
            ],
        ),
        (
            SpawnId.SPIDER_SP1_RANDOM_32,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_32_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_32_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_32_TINT,
            ],
        ),
        (
            SpawnId.SPIDER_SP1_RANDOM_RED_33,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_TINT_R,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.SPIDER_SP1_RANDOM_GREEN_34,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.SPIDER_SP2_RANDOM_35,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ZOMBIE_RANDOM_41,
            [
                RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ZOMBIE_RANDOM_41_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ZOMBIE_RANDOM_41_TINT,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ZOMBIE_RANDOM_41_CONTACT_DAMAGE,
            ],
        ),
    ],
)
def test_build_spawn_plan_random_template_callers_use_exact_native_sites(
    default_spawn_env: SpawnEnv,
    template_id: SpawnId,
    callers: list[RngCallerStatic],
) -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    build_spawn_plan(template_id, Vec2(100.0, 200.0), 0.0, rng, default_spawn_env)

    assert [record.caller for record in rng.records_since()] == callers
