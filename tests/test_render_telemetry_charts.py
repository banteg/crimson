from __future__ import annotations

from crimson.replay.driver import render_telemetry_charts as charts


def test_build_binned_pass_rows_uses_exclusive_parent_pass_timing() -> None:
    frames = [
        {
            "tick_index": 10,
            "pass_ms": {
                "projectiles_effects": 10.0,
                "primary_projectiles": 6.0,
                "effect_pool": 1.0,
                "laser_sight": 1.0,
                "bonus_ui": 5.0,
                "bonus_labels": 1.5,
                "bonus_pickups": 0.5,
            },
        },
    ]
    selected = [
        "projectiles_effects",
        "primary_projectiles",
        "effect_pool",
        "laser_sight",
        "bonus_ui",
        "bonus_labels",
        "bonus_pickups",
    ]

    rows, binned_points, bin_size = charts._build_binned_pass_rows(
        frames=frames,
        selected_passes=selected,
        include_other=False,
    )

    assert binned_points == 1
    assert bin_size == 1
    by_name = {str(row["pass_name"]): float(row["pass_ms"]) for row in rows}

    assert by_name["primary_projectiles"] == 6.0
    assert by_name["effect_pool"] == 1.0
    assert by_name["laser_sight"] == 1.0
    assert by_name["bonus_labels"] == 1.5
    assert by_name["bonus_pickups"] == 0.5
    assert by_name["projectiles_effects"] == 2.0
    assert by_name["bonus_ui"] == 3.0


def test_build_binned_pass_rows_clamps_negative_parent_exclusive_to_zero() -> None:
    frames = [
        {
            "tick_index": 20,
            "pass_ms": {
                "projectiles_effects": 1.0,
                "primary_projectiles": 2.0,
            },
        },
    ]

    rows, _, _ = charts._build_binned_pass_rows(
        frames=frames,
        selected_passes=["projectiles_effects", "primary_projectiles"],
        include_other=False,
    )
    by_name = {str(row["pass_name"]): float(row["pass_ms"]) for row in rows}

    assert "projectiles_effects" not in by_name
    assert by_name["primary_projectiles"] == 2.0
