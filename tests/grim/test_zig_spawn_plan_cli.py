from __future__ import annotations

import json
from typing import Any, cast

import crimson_re.dbg.record as dbg_record
from crimson.cli.root import spawn_template_into_fresh_pool
from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn import RANDOM_HEADING_SENTINEL, SpawnId
from crimson.math_parity import f32
from grim.geom import Vec2

_CREATURE_FIELDS = (
    "index",
    "type_id",
    "ai_mode",
    "flags",
    "pos_x",
    "pos_y",
    "heading",
    "link_index",
    "health",
    "max_health",
    "move_speed",
    "reward_value",
    "size",
    "contact_damage",
)


def _python_creatures(pool: CreaturePool) -> list[tuple[float | int, ...]]:
    return [
        (
            index,
            int(c.type_id),
            int(c.ai_mode),
            int(c.flags),
            c.pos.x,
            c.pos.y,
            c.heading,
            c.link_index,
            c.hp,
            c.max_hp,
            c.move_speed,
            c.reward_value,
            c.size,
            c.contact_damage,
        )
        for index, c in enumerate(pool.entries)
        if c.active
    ]


def _zig_creatures(payload: dict[str, Any]) -> list[tuple[float | int, ...]]:
    rows = []
    for c in cast("list[dict[str, Any]]", payload["creatures"]):
        # JSON carries the shortest float32 repr; parse it back to float32.
        row = {**c, "pos_x": c["pos"]["x"], "pos_y": c["pos"]["y"]}
        rows.append(tuple(f32(row[name]) if isinstance(row[name], float) else row[name] for name in _CREATURE_FIELDS))
    return rows


def _python_spawn_slots(pool: CreaturePool) -> list[tuple[float | int, ...]]:
    return [
        (slot.owner_creature, slot.timer, slot.count, slot.limit, slot.interval, int(slot.child_template_id))
        for slot in pool.spawn_slots
        if slot.owner_creature >= 0
    ]


def _zig_spawn_slots(payload: dict[str, Any]) -> list[tuple[float | int, ...]]:
    return [
        (slot["owner_creature"], f32(slot["timer"]), slot["count"], slot["limit"], f32(slot["interval"]), slot["child_template_id"])
        for slot in cast("list[dict[str, Any]]", payload["spawn_slots"])
    ]


def test_zig_spawn_plan_pool_state_matches_python() -> None:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    cases = [(template_id, 0.0) for template_id in SpawnId if template_id != SpawnId.UNUSED_02]
    cases += [(SpawnId.FORMATION_GRID_ALIEN_GREEN_14, RANDOM_HEADING_SENTINEL), (SpawnId.ZOMBIE_RANDOM_41, RANDOM_HEADING_SENTINEL)]
    for template_id, heading in cases:
        result = dbg_record._run_process(
            [
                str(dbg_record._ZIG_BIN),
                "spawn-plan",
                f"0x{int(template_id):02x}",
                "--json",
                "--seed",
                "0xBEEF",
                "--pos",
                "512,512",
                "--heading",
                str(heading),
            ],
            cwd=dbg_record._REPO_ROOT,
        )
        assert result.returncode == 0, dbg_record._command_detail(result)
        payload = cast("dict[str, Any]", json.loads(result.stdout))
        assert payload["schema_version"] == 1
        assert payload["status"] == "ok"
        assert payload["template_id"] == int(template_id)

        pool, state, _returned = spawn_template_into_fresh_pool(template_id, Vec2(512.0, 512.0), heading, seed=0xBEEF)
        case = f"template 0x{int(template_id):02x} heading={heading}"
        assert _zig_creatures(payload) == _python_creatures(pool), case
        assert _zig_spawn_slots(payload) == _python_spawn_slots(pool), case
        assert payload["effect_count"] == len(state.effects.iter_active()), case
        assert payload["rng_state"] == state.rng.state, case


def test_zig_spawn_plan_rejects_unsupported_template() -> None:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    result = dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "spawn-plan", "0x44", "--json"],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 1
    assert "invalid spawn-plan args: invalid spawn template id" in result.stderr


def test_zig_spawn_plan_human_output_includes_summary() -> None:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    result = dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "spawn-plan", "0x12"],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "template_id=0x12 (18)" in result.stdout
    pool, state, _returned = spawn_template_into_fresh_pool(SpawnId.FORMATION_RING_ALIEN_8_12, Vec2(512.0, 512.0), 0.0, seed=0xBEEF)
    active = sum(creature.active for creature in pool.entries)
    slots = len(_python_spawn_slots(pool))
    assert f"active={active} slots={slots} effects={len(state.effects.iter_active())}" in result.stdout
    assert "creatures:" in result.stdout
