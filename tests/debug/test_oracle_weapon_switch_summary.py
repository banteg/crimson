from __future__ import annotations

import json
from pathlib import Path


def _load_summary() -> dict:
    path = Path("analysis/frida/weapon_switch_trace_summary.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_oracle_summary_has_frames() -> None:
    summary = _load_summary()
    event_counts = summary.get("event_counts", {})
    assert int(event_counts.get("oracle_frame", 0)) > 0


def test_oracle_summary_bonus_pickups() -> None:
    summary = _load_summary()
    counts = summary.get("bonus_apply", {}).get("counts_by_id", {})
    # Session 9 capture includes Nuke (5) and Speed (13).
    assert int(counts.get("5", 0)) >= 1
    assert int(counts.get("13", 0)) >= 1


def test_oracle_player_ranges_sane() -> None:
    summary = _load_summary()
    ranges = summary.get("oracle", {}).get("player_ranges", {}).get("0", {})
    clip_range = ranges.get("clip_size", {})
    ammo_range = ranges.get("ammo", {})
    weapon_range = ranges.get("weapon_id", {})

    assert float(clip_range.get("min", 0)) >= 3.0
    assert float(clip_range.get("max", 0)) >= 20.0
    assert float(ammo_range.get("min", -1)) >= 0.0
    assert float(weapon_range.get("min", 0)) <= 1.0
    assert float(weapon_range.get("max", 0)) >= 30.0
