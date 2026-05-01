from __future__ import annotations

import json
from typing import Any, cast

import crimson.dbg.record as dbg_record
from crimson.creatures.spawn import SpawnEnv, SpawnId, build_spawn_plan
from grim.geom import Vec2
from grim.rand import Crand


def test_zig_spawn_plan_json_matches_python_summary() -> None:
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    cases = (
        SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
        SpawnId.FORMATION_RING_ALIEN_8_12,
        SpawnId.ALIEN_CONST_WEAPON_BONUS_27,
    )

    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    for template_id in cases:
        expected = build_spawn_plan(template_id, Vec2(512.0, 512.0), 0.0, Crand(0xBEEF), env)
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
            ],
            cwd=dbg_record._REPO_ROOT,
        )

        assert result.returncode == 0, dbg_record._command_detail(result)
        payload = cast("dict[str, Any]", json.loads(result.stdout))
        assert payload["schema_version"] == 1
        assert payload["status"] == "ok"
        assert payload["template_id"] == int(template_id)
        assert payload["active_count"] == len(expected.creatures)
        assert payload["spawn_slot_count"] == len(expected.spawn_slots)


def test_zig_spawn_plan_rejects_unsupported_template() -> None:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    result = dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "spawn-plan", "0x02", "--json"],
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
    assert "active=9 slots=0" in result.stdout
    assert "creatures:" in result.stdout
