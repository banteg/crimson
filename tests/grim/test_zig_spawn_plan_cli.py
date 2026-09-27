from __future__ import annotations

import json
from typing import Any, cast

import crimson.dbg.record as dbg_record
from crimson.creatures.spawn import SpawnEnv, SpawnId, build_spawn_plan
from grim.geom import Vec2
from grim.rand import Crand

_ENV = SpawnEnv(hardcore=False, quest_fail_retry_count=0)


def _python_plan(template_id: SpawnId):
    return build_spawn_plan(template_id, Vec2(512.0, 512.0), 0.0, Crand(0xBEEF), _ENV)


def test_zig_spawn_plan_json_matches_python_summary() -> None:
    cases = (
        SpawnId.DEN_ALIEN_BASIC_07,
        SpawnId.FORMATION_RING_ALIEN_8_12,
        SpawnId.ALIEN_BONUS_CARRIER_27,
    )

    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    for template_id in cases:
        expected = _python_plan(template_id)
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
                "--no-demo-mode-active",
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
        assert payload["demo_mode_active"] is False
        assert payload["effect_count"] == sum(effect.count for effect in expected.effects)


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
        [str(dbg_record._ZIG_BIN), "spawn-plan", "0x12", "--no-demo-mode-active"],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "template_id=0x12 (18)" in result.stdout
    expected = _python_plan(SpawnId.FORMATION_RING_ALIEN_8_12)
    effect_count = sum(effect.count for effect in expected.effects)
    assert f"active={len(expected.creatures)} slots={len(expected.spawn_slots)} effects={effect_count}" in result.stdout
    assert "creatures:" in result.stdout
