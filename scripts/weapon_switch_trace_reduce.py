from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
import struct


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return int(value)
    return None


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _stringify_keys(mapping: dict[int, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in sorted(mapping.items(), key=lambda item: item[0])}


def _update_range(ranges: dict[str, dict[str, float]], key: str, value: Any) -> None:
    if value is None:
        return
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return
    entry = ranges.get(key)
    if entry is None:
        ranges[key] = {"min": numeric, "max": numeric}
    else:
        entry["min"] = min(entry["min"], numeric)
        entry["max"] = max(entry["max"], numeric)


def _maybe_decode_float_bits(key: str, value: Any) -> Any:
    if key not in ("ammo", "clip_size"):
        return value
    if not isinstance(value, (int, float)):
        return value
    raw = int(value)
    if raw < 0 or raw > 0xFFFFFFFF:
        return value
    if raw < (1 << 20):
        return value
    try:
        return struct.unpack("<f", struct.pack("<I", raw & 0xFFFFFFFF))[0]
    except struct.error:
        return value


def summarize(log_path: Path) -> dict[str, Any]:
    event_counts: Counter[str] = Counter()
    event_with_weapon: Counter[str] = Counter()
    weapon_snapshots: dict[int, dict[str, Any]] = {}
    weapon_ids: set[int] = set()
    weapon_names: dict[int, str] = {}
    weapon_switches: list[dict[str, Any]] = []

    projectile_types_by_weapon: dict[int, set[int]] = defaultdict(set)
    projectile_counts_by_weapon: Counter[int] = Counter()
    projectile_counts_by_type: Counter[int] = Counter()

    secondary_types_by_weapon: dict[int, set[int]] = defaultdict(set)
    secondary_counts_by_weapon: Counter[int] = Counter()
    secondary_counts_by_type: Counter[int] = Counter()

    particle_counts_by_weapon: Counter[int] = Counter()
    particle_slow_counts_by_weapon: Counter[int] = Counter()

    effect_counts_by_weapon: Counter[int] = Counter()
    effect_ids_by_weapon: dict[int, set[int]] = defaultdict(set)

    sfx_counts_by_weapon: Counter[int] = Counter()
    sfx_ids_by_weapon: dict[int, set[int]] = defaultdict(set)
    sfx_counts_by_id: Counter[int] = Counter()

    damage_type_counts: Counter[int] = Counter()
    radius_damage_type_counts: Counter[int] = Counter()

    weapon_fire_counts: Counter[int] = Counter()
    bonus_apply_counts: Counter[int] = Counter()
    bonus_apply_samples: list[dict[str, Any]] = []
    energizer_samples: list[dict[str, Any]] = []

    oracle_frame_count = 0
    oracle_player_ranges: dict[int, dict[str, dict[str, float]]] = defaultdict(dict)
    oracle_bonus_timer_max: dict[str, float] = defaultdict(float)
    oracle_creature_samples = 0
    oracle_creature_max = 0

    start_event: dict[str, Any] | None = None
    first_ts: int | None = None
    last_ts: int | None = None

    for obj in iter_jsonl(log_path):
        event = obj.get("event") or obj.get("tag")
        if not isinstance(event, str):
            continue
        event_counts[event] += 1

        ts = _as_int(obj.get("ts"))
        if ts is not None:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)

        if event == "start":
            start_event = {
                "config": obj.get("config"),
                "frida": obj.get("frida"),
                "process": obj.get("process"),
                "module": obj.get("module"),
                "link_base": obj.get("link_base"),
                "exe": obj.get("exe"),
                "grim": obj.get("grim"),
                "out_path": obj.get("out_path"),
                "ts": ts,
            }

        weapon_id: int | None = None
        weapon_obj = obj.get("weapon")
        if isinstance(weapon_obj, dict):
            weapon_id = _as_int(weapon_obj.get("weapon_id"))
            if weapon_id is not None:
                weapon_ids.add(weapon_id)
                weapon_snapshots[weapon_id] = weapon_obj
                name = weapon_obj.get("name")
                if isinstance(name, str) and name:
                    weapon_names[weapon_id] = name
        else:
            weapon_id = _as_int(obj.get("weapon_id"))
            if weapon_id is not None:
                weapon_ids.add(weapon_id)

        if weapon_id is not None:
            event_with_weapon[event] += 1

        if event == "weapon_switch":
            weapon_switches.append(
                {
                    "from": _as_int(obj.get("from")),
                    "to": _as_int(obj.get("to")),
                    "direction": _as_int(obj.get("direction")),
                }
            )
        elif event == "weapon_fire" and weapon_id is not None:
            weapon_fire_counts[weapon_id] += 1
        elif event == "bonus_apply":
            entry = obj.get("entry")
            if isinstance(entry, dict):
                bonus_id = _as_int(entry.get("bonus_id"))
                if bonus_id is not None:
                    bonus_apply_counts[bonus_id] += 1
                if len(bonus_apply_samples) < 12:
                    bonus_apply_samples.append(entry)
                if bonus_id == 2 and len(energizer_samples) < 6:
                    energizer_samples.append(entry)
        elif event == "projectile_spawn":
            type_id = _as_int(obj.get("type_id"))
            if type_id is not None:
                projectile_counts_by_type[type_id] += 1
                if weapon_id is not None:
                    projectile_types_by_weapon[weapon_id].add(type_id)
                    projectile_counts_by_weapon[weapon_id] += 1
        elif event == "secondary_projectile_spawn":
            type_id = _as_int(obj.get("type_id"))
            if type_id is not None:
                secondary_counts_by_type[type_id] += 1
                if weapon_id is not None:
                    secondary_types_by_weapon[weapon_id].add(type_id)
                    secondary_counts_by_weapon[weapon_id] += 1
        elif event == "particle_spawn":
            if weapon_id is not None:
                particle_counts_by_weapon[weapon_id] += 1
                if obj.get("slow"):
                    particle_slow_counts_by_weapon[weapon_id] += 1
        elif event == "effect_spawn":
            effect_id = _as_int(obj.get("effect_id"))
            if weapon_id is not None:
                effect_counts_by_weapon[weapon_id] += 1
                if effect_id is not None:
                    effect_ids_by_weapon[weapon_id].add(effect_id)
        elif event in ("sfx_play", "sfx_play_exclusive", "sfx_play_panned"):
            sfx_id = _as_int(obj.get("sfx_id"))
            if sfx_id is not None:
                sfx_counts_by_id[sfx_id] += 1
                if weapon_id is not None:
                    sfx_counts_by_weapon[weapon_id] += 1
                    sfx_ids_by_weapon[weapon_id].add(sfx_id)
        elif event == "creature_damage":
            damage_type = _as_int(obj.get("damage_type"))
            if damage_type is not None:
                damage_type_counts[damage_type] += 1
        elif event == "creature_damage_radius":
            damage_type = _as_int(obj.get("damage_type"))
            if damage_type is not None:
                radius_damage_type_counts[damage_type] += 1
        elif event == "oracle_frame":
            oracle_frame_count += 1
            players = obj.get("players")
            if isinstance(players, list):
                for player in players:
                    if not isinstance(player, dict):
                        continue
                    idx = _as_int(player.get("index"))
                    if idx is None:
                        continue
                    ranges = oracle_player_ranges[idx]
                    for key in (
                        "health",
                        "weapon_id",
                        "clip_size",
                        "ammo",
                        "reload_active",
                        "reload_timer",
                        "reload_timer_max",
                        "shot_cooldown",
                        "spread_heat",
                        "xp",
                        "xp_delta",
                        "level",
                    ):
                        value = _maybe_decode_float_bits(key, player.get(key))
                        _update_range(ranges, key, value)
                    perk = player.get("perk_timers")
                    if isinstance(perk, dict):
                        for key in ("hot_tempered", "man_bomb", "living_fortress", "fire_cough"):
                            _update_range(ranges, f"perk_{key}", perk.get(key))
                    bonus = player.get("bonus_timers")
                    if isinstance(bonus, dict):
                        for key in ("speed_bonus", "shield", "fire_bullets"):
                            _update_range(ranges, f"bonus_{key}", bonus.get(key))
            creatures = obj.get("creatures")
            if isinstance(creatures, list):
                oracle_creature_samples += len(creatures)
                oracle_creature_max = max(oracle_creature_max, len(creatures))
            bonus_timers = obj.get("bonus_timers")
            if isinstance(bonus_timers, dict):
                for key, value in bonus_timers.items():
                    val = _as_float(value)
                    if val is None:
                        continue
                    oracle_bonus_timer_max[key] = max(oracle_bonus_timer_max.get(key, 0.0), val)

    weapon_summary = []
    for weapon_id in sorted(weapon_ids):
        weapon_summary.append(
            {
                "weapon_id": weapon_id,
                "name": weapon_names.get(weapon_id),
                "weapon": weapon_snapshots.get(weapon_id),
                "weapon_fire_count": weapon_fire_counts.get(weapon_id, 0),
                "projectile_types": sorted(projectile_types_by_weapon.get(weapon_id, set())),
                "projectile_count": projectile_counts_by_weapon.get(weapon_id, 0),
                "secondary_types": sorted(secondary_types_by_weapon.get(weapon_id, set())),
                "secondary_count": secondary_counts_by_weapon.get(weapon_id, 0),
                "particle_count": particle_counts_by_weapon.get(weapon_id, 0),
                "particle_slow_count": particle_slow_counts_by_weapon.get(weapon_id, 0),
                "effect_count": effect_counts_by_weapon.get(weapon_id, 0),
                "effect_ids": sorted(effect_ids_by_weapon.get(weapon_id, set())),
                "sfx_count": sfx_counts_by_weapon.get(weapon_id, 0),
                "sfx_ids": sorted(sfx_ids_by_weapon.get(weapon_id, set())),
            }
        )

    duration_ms = None
    if first_ts is not None and last_ts is not None:
        duration_ms = last_ts - first_ts

    return {
        "script": "scripts/frida/weapon_switch_trace.js",
        "source_log": str(log_path),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "session": {
            "start": start_event,
            "duration_ms": duration_ms,
            "first_ts": first_ts,
            "last_ts": last_ts,
        },
        "event_counts": dict(event_counts),
        "event_with_weapon": dict(event_with_weapon),
        "weapon_ids": sorted(weapon_ids),
        "weapon_switches": weapon_switches,
        "projectiles": {
            "counts_by_type": _stringify_keys(projectile_counts_by_type),
            "counts_by_weapon": _stringify_keys(projectile_counts_by_weapon),
            "types_by_weapon": _stringify_keys({k: sorted(v) for k, v in projectile_types_by_weapon.items()}),
        },
        "secondary_projectiles": {
            "counts_by_type": _stringify_keys(secondary_counts_by_type),
            "counts_by_weapon": _stringify_keys(secondary_counts_by_weapon),
            "types_by_weapon": _stringify_keys({k: sorted(v) for k, v in secondary_types_by_weapon.items()}),
        },
        "particles": {
            "counts_by_weapon": _stringify_keys(particle_counts_by_weapon),
            "slow_counts_by_weapon": _stringify_keys(particle_slow_counts_by_weapon),
        },
        "effects": {
            "counts_by_weapon": _stringify_keys(effect_counts_by_weapon),
            "ids_by_weapon": _stringify_keys({k: sorted(v) for k, v in effect_ids_by_weapon.items()}),
        },
        "sfx": {
            "counts_by_id": _stringify_keys(sfx_counts_by_id),
            "counts_by_weapon": _stringify_keys(sfx_counts_by_weapon),
            "ids_by_weapon": _stringify_keys({k: sorted(v) for k, v in sfx_ids_by_weapon.items()}),
        },
        "damage": {
            "direct_counts_by_type": _stringify_keys(damage_type_counts),
            "radius_counts_by_type": _stringify_keys(radius_damage_type_counts),
        },
        "bonus_apply": {
            "counts_by_id": _stringify_keys(bonus_apply_counts),
            "samples": bonus_apply_samples,
            "energizer_samples": energizer_samples,
        },
        "oracle": {
            "frame_count": oracle_frame_count,
            "player_ranges": {
                str(idx): ranges for idx, ranges in sorted(oracle_player_ranges.items(), key=lambda item: item[0])
            },
            "bonus_timer_max": oracle_bonus_timer_max,
            "creature_samples": oracle_creature_samples,
            "creature_max_per_frame": oracle_creature_max,
        },
        "weapon_summary": weapon_summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize weapon_switch_trace JSONL logs.")
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("artifacts/frida/share/weapon_switch_trace.jsonl"),
        help="Path to the weapon_switch_trace.jsonl capture.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("analysis/frida/weapon_switch_trace_summary.json"),
        help="Output JSON summary path.",
    )
    args = parser.parse_args()

    summary = summarize(args.log)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
