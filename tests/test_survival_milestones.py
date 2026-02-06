from __future__ import annotations

import math

import pytest

from crimson.creatures.spawn import advance_survival_spawn_stage


@pytest.mark.parametrize(
    ("stage", "level", "expected_stage", "expected_count"),
    [
        (0, 4, 0, 0),
        (0, 5, 1, 2),
        (0, 20, 7, 29),  # cascades through stages when level is already high
        (1, 8, 1, 0),
        (1, 9, 2, 1),
        (2, 10, 2, 0),
        (2, 11, 3, 12),
        (3, 13, 4, 4),
        (4, 15, 5, 8),
        (5, 17, 6, 1),
        (6, 19, 7, 1),
        (7, 21, 8, 2),
        (8, 26, 9, 8),
        (9, 31, 9, 0),
        (9, 32, 10, 10),
    ],
)
def test_advance_survival_spawn_stage_thresholds(
    stage: int,
    level: int,
    expected_stage: int,
    expected_count: int,
) -> None:
    new_stage, spawns = advance_survival_spawn_stage(stage, player_level=level)
    assert new_stage == expected_stage
    assert len(spawns) == expected_count


def test_advance_survival_spawn_stage_stage2_grid_positions() -> None:
    stage, spawns = advance_survival_spawn_stage(2, player_level=11)
    assert stage == 3
    assert len(spawns) == 12
    assert {s.template_id for s in spawns} == {0x35}
    assert {s.heading for s in spawns} == {math.pi}

    assert spawns[0].pos.x == pytest.approx(1088.0, abs=1e-9)
    assert spawns[0].pos.y == pytest.approx(256.0, abs=1e-9)

    assert spawns[-1].pos.x == pytest.approx(1088.0, abs=1e-9)
    assert spawns[-1].pos.y == pytest.approx(256.0 + 11.0 * (128.0 / 3.0), abs=1e-9)


def test_advance_survival_spawn_stage_stage9_final_wave() -> None:
    stage, spawns = advance_survival_spawn_stage(9, player_level=32)
    assert stage == 10
    assert len(spawns) == 10

    assert [s.template_id for s in spawns[:2]] == [0x3A, 0x3A]
    assert spawns[0].pos.x == pytest.approx(1088.0, abs=1e-9)
    assert spawns[0].pos.y == pytest.approx(512.0, abs=1e-9)
    assert spawns[1].pos.x == pytest.approx(-64.0, abs=1e-9)
    assert spawns[1].pos.y == pytest.approx(512.0, abs=1e-9)

    top = spawns[2:6]
    bottom = spawns[6:10]
    assert {s.template_id for s in top} == {0x3C}
    assert {s.template_id for s in bottom} == {0x3C}
    for y in (s.pos.y for s in top):
        assert y == pytest.approx(-64.0, abs=1e-9)
    for y in (s.pos.y for s in bottom):
        assert y == pytest.approx(1088.0, abs=1e-9)
