from __future__ import annotations

import argparse
import bisect
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LINK_BASE_EXE = 0x00400000
_HEX_NO_PREFIX_RE = re.compile(r"^[0-9a-fA-F]{8}$")



def parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.startswith(("0x", "0X")):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def parse_static_address(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.startswith(("0x", "0X")):
            return int(text, 16)
        if _HEX_NO_PREFIX_RE.fullmatch(text):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


@dataclass
class ExeInfo:
    base: int | None = None
    size: int | None = None


@dataclass(frozen=True)
class FunctionEntry:
    start: int
    name: str


class FunctionIndex:
    def __init__(self, function_map_path: Path) -> None:
        data = json.loads(function_map_path.read_text(encoding="utf-8"))
        rows: list[Any]
        if isinstance(data, dict):
            maybe = data.get("functions")
            if isinstance(maybe, list):
                rows = maybe
            else:
                maybe = data.get("entries")
                rows = maybe if isinstance(maybe, list) else []
        elif isinstance(data, list):
            rows = data
        else:
            rows = []

        entries: list[FunctionEntry] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            addr = parse_static_address(row.get("address"))
            if addr is None:
                continue
            name = row.get("name")
            if not isinstance(name, str) or not name:
                name = f"FUN_{addr:08x}"
            entries.append(FunctionEntry(start=addr, name=name))

        entries.sort(key=lambda e: e.start)
        self.entries = entries
        self.starts = [entry.start for entry in entries]

    def lookup(self, static_addr: int | None) -> FunctionEntry | None:
        if static_addr is None:
            return None
        idx = bisect.bisect_right(self.starts, static_addr) - 1
        if idx < 0:
            return None
        entry = self.entries[idx]
        if idx + 1 < len(self.entries) and static_addr >= self.entries[idx + 1].start:
            return None
        return entry


class SymbolIndex:
    def __init__(self, data_map_path: Path) -> None:
        data = json.loads(data_map_path.read_text(encoding="utf-8"))
        rows = data.get("entries") if isinstance(data, dict) else []
        if not isinstance(rows, list):
            rows = []

        self.by_addr: dict[int, str] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("program") != "crimsonland.exe":
                continue
            addr = parse_int(row.get("address"))
            name = row.get("name")
            if addr is None or not isinstance(name, str) or not name:
                continue
            self.by_addr[addr] = name

    def name_for(self, static_addr: int | None) -> str | None:
        if static_addr is None:
            return None
        return self.by_addr.get(static_addr)


def runtime_to_static(addr: int | None, exe: ExeInfo) -> int | None:
    if addr is None:
        return None
    if exe.base is None:
        return addr
    if exe.size is not None and not (exe.base <= addr < exe.base + exe.size):
        return addr
    return LINK_BASE_EXE + (addr - exe.base)


def normalize_pointer(ptr_text: Any, exe: ExeInfo) -> tuple[int | None, int | None]:
    runtime = parse_int(ptr_text)
    return runtime, runtime_to_static(runtime, exe)


def caller_to_static(caller: Any) -> int | None:
    if not isinstance(caller, str):
        return None
    text = caller.strip()
    if "+0x" not in text:
        return None
    module, off = text.split("+0x", 1)
    if module.lower() != "crimsonland.exe":
        return None
    try:
        return LINK_BASE_EXE + int(off, 16)
    except ValueError:
        return None


def top_counter(counter: Counter[Any], limit: int) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in counter.most_common(limit)]


def parse_sfx_function_and_id(key: str) -> tuple[str, str, int | None]:
    event, fn_name, raw_id = (key.split("|", 2) + ["", ""])[:3]
    return event, fn_name, parse_int(raw_id)


def extract_sfx_id_candidates(
    by_function: Counter[str], by_function_and_id: Counter[str], min_total: int = 20, min_share: float = 0.9
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for fn_key, total in by_function.items():
        if total < min_total:
            continue
        prefix = f"{fn_key}|"
        id_counts: Counter[int | None] = Counter()
        for key, count in by_function_and_id.items():
            if key.startswith(prefix):
                _event, _fn_name, sid = parse_sfx_function_and_id(key)
                id_counts[sid] += count
        if not id_counts:
            continue
        top_id, top_count = id_counts.most_common(1)[0]
        share = float(top_count) / float(total) if total else 0.0
        if share < min_share:
            continue
        event, fn_name = (fn_key.split("|", 1) + [""])[:2]
        out.append(
            {
                "event": event,
                "function": fn_name,
                "id": top_id,
                "count": top_count,
                "total": total,
                "share": round(share, 4),
            }
        )
    out.sort(key=lambda row: (row["total"], row["count"]), reverse=True)
    return out


def summarize(log_path: Path, symbols: SymbolIndex, functions: FunctionIndex, top_n: int) -> dict[str, Any]:
    exe = ExeInfo()

    event_counts: Counter[str] = Counter()
    state_target_counts: Counter[int] = Counter()
    state_transition_counts: Counter[str] = Counter()
    snapshot_state_counts: Counter[int] = Counter()
    mode_counts: Counter[str] = Counter()
    mode_state_counts: Counter[str] = Counter()

    bonus_id_counts: Counter[int] = Counter()
    bonus_label_counts: Counter[str] = Counter()
    bonus_icon_counts: Counter[str] = Counter()
    bonus_timer_ptr_counts: Counter[str] = Counter()

    weapon_assign_counts: Counter[str] = Counter()
    projectile_type_pairs: Counter[str] = Counter()
    projectile_owner_counts: Counter[int] = Counter()
    projectile_override_true = 0
    projectile_override_false = 0

    ui_delta_state_counts: Counter[int] = Counter()
    ui_delta_field_counts: Counter[str] = Counter()
    ui_delta_offset_counts: Counter[str] = Counter()
    ui_delta_block_counts: Counter[str] = Counter()

    ui_element_state_counts: Counter[str] = Counter()

    quest_results_seen = 0
    quest_results_last: dict[str, Any] | None = None
    quest_results_unlock_weapon_counts: Counter[int] = Counter()
    quest_results_unlock_perk_counts: Counter[int] = Counter()
    quest_results_final_time_values: list[int] = []

    jinxed_vals: list[float] = []
    lean_mean_vals: list[float] = []
    doctor_target_counts: Counter[int] = Counter()

    mem_watch_access_count = 0
    mem_watch_range_counts: Counter[str] = Counter()

    sfx_func_counts: Counter[str] = Counter()
    sfx_func_id_counts: Counter[str] = Counter()

    clip_samples = 0
    clip_bitpattern_samples = 0
    ammo_samples = 0
    ammo_bitpattern_samples = 0

    ts_min: int | None = None
    ts_max: int | None = None

    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue

            event = obj.get("event")
            if not isinstance(event, str):
                event = "<no_event>"
            event_counts[event] += 1

            ts = parse_int(obj.get("ts_ms"))
            if ts is not None:
                ts_min = ts if ts_min is None else min(ts_min, ts)
                ts_max = ts if ts_max is None else max(ts_max, ts)

            if event == "start":
                exe_row = obj.get("exe")
                if isinstance(exe_row, dict):
                    exe.base = parse_int(exe_row.get("base"))
                    exe.size = parse_int(exe_row.get("size"))

            elif event == "game_state_set":
                target = parse_int(obj.get("target_state"))
                before = obj.get("before") if isinstance(obj.get("before"), dict) else {}
                before_id = parse_int(before.get("id"))
                if target is not None:
                    state_target_counts[target] += 1
                if before_id is not None and target is not None:
                    state_transition_counts[f"{before_id}->{target}"] += 1

            elif event == "snapshot_compact":
                globals_row = obj.get("globals") if isinstance(obj.get("globals"), dict) else {}
                sid = parse_int(globals_row.get("game_state_id"))
                if sid is not None:
                    snapshot_state_counts[sid] += 1

                players = obj.get("players")
                if isinstance(players, list) and players:
                    p0 = players[0]
                    if isinstance(p0, dict):
                        clip_i32 = parse_int(p0.get("clip_size_i32"))
                        clip_f32 = p0.get("clip_size_f32")
                        if clip_i32 is not None and isinstance(clip_f32, (int, float)) and math.isfinite(float(clip_f32)):
                            clip_samples += 1
                            if abs(float(clip_f32) - round(float(clip_f32))) < 1e-6 and clip_i32 != int(round(float(clip_f32))):
                                clip_bitpattern_samples += 1

                        ammo_i32 = parse_int(p0.get("ammo_i32"))
                        ammo_f32 = p0.get("ammo_f32")
                        if ammo_i32 is not None and isinstance(ammo_f32, (int, float)) and math.isfinite(float(ammo_f32)):
                            ammo_samples += 1
                            if abs(float(ammo_f32) - round(float(ammo_f32))) < 1e-6 and ammo_i32 != int(round(float(ammo_f32))):
                                ammo_bitpattern_samples += 1

            elif event == "mode_tick":
                mode = obj.get("mode_fn")
                sid = parse_int(obj.get("state_id"))
                if isinstance(mode, str) and mode:
                    mode_counts[mode] += 1
                    if sid is not None:
                        mode_state_counts[f"{mode}@{sid}"] += 1

            elif event == "bonus_apply":
                bonus_id = parse_int(obj.get("bonus_id"))
                if bonus_id is not None:
                    bonus_id_counts[bonus_id] += 1

            elif event == "bonus_hud_slot_activate":
                args = obj.get("args") if isinstance(obj.get("args"), dict) else {}
                label = args.get("label") if isinstance(args.get("label"), str) else "<unknown>"
                icon = parse_int(args.get("icon_id"))
                bonus_label_counts[label] += 1
                if icon is not None:
                    bonus_icon_counts[f"{label}|icon:{icon}"] += 1

                for which in ("timer_ptr", "alt_timer_ptr"):
                    _runtime, static = normalize_pointer(args.get(which), exe)
                    if static is None:
                        continue
                    name = symbols.name_for(static)
                    display = f"{label}|{which}|0x{static:08x}|{name or '?'}"
                    bonus_timer_ptr_counts[display] += 1

            elif event == "weapon_assign_player":
                weapon = obj.get("weapon") if isinstance(obj.get("weapon"), dict) else {}
                wid = parse_int(obj.get("weapon_id"))
                wname = weapon.get("name") if isinstance(weapon.get("name"), str) else None
                if wid is not None:
                    weapon_assign_counts[f"{wid}:{wname or 'unknown'}"] += 1

            elif event == "projectile_spawn":
                req = parse_int(obj.get("requested_type_id"))
                actual_row = obj.get("actual") if isinstance(obj.get("actual"), dict) else {}
                actual = parse_int(actual_row.get("type_id"))
                owner = parse_int(obj.get("owner_id"))
                if req is not None or actual is not None:
                    projectile_type_pairs[f"{req}->{actual}"] += 1
                if owner is not None:
                    projectile_owner_counts[owner] += 1
                over = obj.get("type_overridden")
                if over is True:
                    projectile_override_true += 1
                elif over is False:
                    projectile_override_false += 1

            elif event == "ui_subtemplate_delta":
                sid = parse_int(obj.get("state_id"))
                if sid is not None:
                    ui_delta_state_counts[sid] += 1
                changes = obj.get("changes")
                if isinstance(changes, list):
                    for change in changes:
                        if not isinstance(change, dict):
                            continue
                        static_va = change.get("static_va")
                        static_addr = parse_static_address(static_va) if isinstance(static_va, str) else None
                        static_sym = symbols.name_for(static_addr)
                        if isinstance(static_va, str):
                            if static_addr is None:
                                ui_delta_offset_counts[static_va] += 1
                            else:
                                ui_delta_offset_counts[f"0x{static_addr:08x}|{static_sym or '?'}"] += 1

                        decode = change.get("decode")
                        if not isinstance(decode, dict):
                            continue

                        block = parse_int(decode.get("block"))
                        if block is not None:
                            ui_delta_block_counts[f"state:{sid}|block:{block}"] += 1

                        slot = parse_int(decode.get("slot"))
                        slot_field = decode.get("slot_field") if isinstance(decode.get("slot_field"), str) else None
                        block_field = decode.get("field") if isinstance(decode.get("field"), str) else None
                        if slot is not None and slot_field:
                            field_name = f"{slot_field}|{static_sym}" if static_sym else slot_field
                            ui_delta_field_counts[f"state:{sid}|block:{block}|slot:{slot}|{field_name}"] += 1
                        elif block_field:
                            field_name = f"{block_field}|{static_sym}" if static_sym else block_field
                            ui_delta_field_counts[f"state:{sid}|block:{block}|{field_name}"] += 1

            elif event == "ui_element_render_input":
                sid = parse_int(obj.get("state_id"))
                static_addr = parse_int(obj.get("element_static_va"))
                sym = symbols.name_for(static_addr)
                ui_element_state_counts[f"state:{sid}|0x{(static_addr or 0):08x}|{sym or '?'}"] += 1

            elif event == "quest_results_reveal_delta":
                compact = obj.get("compact") if isinstance(obj.get("compact"), dict) else {}
                if compact:
                    quest_results_seen += 1
                    quest_results_last = compact
                    uw = parse_int(compact.get("unlock_weapon_id"))
                    up = parse_int(compact.get("unlock_perk_id"))
                    ft = parse_int(compact.get("final_time_ms"))
                    if uw is not None:
                        quest_results_unlock_weapon_counts[uw] += 1
                    if up is not None:
                        quest_results_unlock_perk_counts[up] += 1
                    if ft is not None:
                        quest_results_final_time_values.append(ft)

            elif event == "perks_update_effects_delta":
                compact = obj.get("compact") if isinstance(obj.get("compact"), dict) else {}
                jinxed = compact.get("perk_jinxed_proc_timer_s")
                lean = compact.get("perk_lean_mean_exp_tick_timer_s")
                doctor = parse_int(compact.get("perk_doctor_target_creature_id"))
                if isinstance(jinxed, (int, float)) and math.isfinite(float(jinxed)):
                    jinxed_vals.append(float(jinxed))
                if isinstance(lean, (int, float)) and math.isfinite(float(lean)):
                    lean_mean_vals.append(float(lean))
                if doctor is not None:
                    doctor_target_counts[doctor] += 1

            elif event == "mem_watch_access":
                mem_watch_access_count += 1
                range_name = obj.get("range") if isinstance(obj.get("range"), str) else "<unknown>"
                mem_watch_range_counts[range_name] += 1

            elif event in ("sfx_play", "sfx_play_panned", "sfx_play_exclusive"):
                sid = parse_int(obj.get("arg0_i32")) if event == "sfx_play_panned" else parse_int(obj.get("id_i32"))
                static_addr = caller_to_static(obj.get("caller"))
                fn = functions.lookup(static_addr)
                fn_name = fn.name if fn else "<unknown>"
                sfx_func_counts[f"{event}|{fn_name}"] += 1
                sfx_func_id_counts[f"{event}|{fn_name}|{sid}"] += 1

    duration_s = None
    if ts_min is not None and ts_max is not None and ts_max >= ts_min:
        duration_s = (ts_max - ts_min) / 1000.0

    quest_final_min = min(quest_results_final_time_values) if quest_results_final_time_values else None
    quest_final_max = max(quest_results_final_time_values) if quest_results_final_time_values else None
    sfx_id_candidates = extract_sfx_id_candidates(sfx_func_counts, sfx_func_id_counts, min_total=20, min_share=0.9)

    return {
        "source_log": str(log_path),
        "source_log_size_bytes": log_path.stat().st_size,
        "timeline": {
            "ts_min": ts_min,
            "ts_max": ts_max,
            "duration_s": duration_s,
        },
        "event_counts": dict(event_counts),
        "state": {
            "game_state_set_target_counts": dict(state_target_counts),
            "game_state_set_transition_counts": dict(state_transition_counts),
            "snapshot_state_counts": dict(snapshot_state_counts),
            "mode_tick_counts": dict(mode_counts),
            "mode_state_counts": dict(mode_state_counts),
        },
        "bonus": {
            "bonus_apply_id_counts": dict(bonus_id_counts),
            "bonus_hud_label_counts": dict(bonus_label_counts),
            "bonus_hud_icon_counts": dict(bonus_icon_counts),
            "bonus_hud_timer_ptr_counts": dict(bonus_timer_ptr_counts),
        },
        "weapon_and_projectile": {
            "weapon_assign_counts": dict(weapon_assign_counts),
            "projectile_type_pairs": dict(projectile_type_pairs),
            "projectile_owner_counts": dict(projectile_owner_counts),
            "projectile_override_true": projectile_override_true,
            "projectile_override_false": projectile_override_false,
        },
        "quest_results": {
            "samples": quest_results_seen,
            "last": quest_results_last,
            "unlock_weapon_counts": dict(quest_results_unlock_weapon_counts),
            "unlock_perk_counts": dict(quest_results_unlock_perk_counts),
            "final_time_ms_min": quest_final_min,
            "final_time_ms_max": quest_final_max,
        },
        "perk_timers": {
            "samples": len(jinxed_vals),
            "jinxed_min": min(jinxed_vals) if jinxed_vals else None,
            "jinxed_max": max(jinxed_vals) if jinxed_vals else None,
            "lean_mean_min": min(lean_mean_vals) if lean_mean_vals else None,
            "lean_mean_max": max(lean_mean_vals) if lean_mean_vals else None,
            "doctor_target_counts": dict(doctor_target_counts),
        },
        "ui_subtemplate": {
            "delta_state_counts": dict(ui_delta_state_counts),
            "top_offset_changes": top_counter(ui_delta_offset_counts, top_n),
            "top_field_changes": top_counter(ui_delta_field_counts, top_n),
            "top_block_changes": top_counter(ui_delta_block_counts, top_n),
            "top_ui_elements": top_counter(ui_element_state_counts, top_n),
        },
        "mem_watch": {
            "access_count": mem_watch_access_count,
            "range_counts": dict(mem_watch_range_counts),
        },
        "sfx": {
            "by_function": dict(sfx_func_counts),
            "by_function_and_id": dict(sfx_func_id_counts),
            "top_by_function": top_counter(sfx_func_counts, top_n),
            "top_by_function_and_id": top_counter(sfx_func_id_counts, top_n),
            "high_confidence_function_ids": sfx_id_candidates,
        },
        "typing_artifacts": {
            "clip_samples": clip_samples,
            "clip_bitpattern_samples": clip_bitpattern_samples,
            "ammo_samples": ammo_samples,
            "ammo_bitpattern_samples": ammo_bitpattern_samples,
        },
    }


def build_report(summary: dict[str, Any], top_n: int) -> str:
    lines: list[str] = []

    duration = summary.get("timeline", {}).get("duration_s")
    lines.append("# Gameplay state capture report")
    lines.append("")
    lines.append(f"- log: `{summary.get('source_log')}`")
    lines.append(f"- size: `{summary.get('source_log_size_bytes')}` bytes")
    lines.append(f"- duration: `{duration:.2f}` s" if isinstance(duration, (int, float)) else "- duration: unknown")
    lines.append("")

    event_counts = Counter(summary.get("event_counts") or {})
    lines.append("## Event volume")
    for key, count in event_counts.most_common(top_n):
        lines.append(f"- `{key}`: {count}")
    lines.append("")

    state = summary.get("state") or {}
    target_counts = Counter(state.get("game_state_set_target_counts") or {})
    transition_counts = Counter(state.get("game_state_set_transition_counts") or {})
    snapshot_counts = Counter(state.get("snapshot_state_counts") or {})
    lines.append("## State coverage")
    lines.append("- game_state_set targets:")
    for key, count in target_counts.most_common(top_n):
        lines.append(f"  - `{key}`: {count}")
    lines.append("- top transitions:")
    for key, count in transition_counts.most_common(top_n):
        lines.append(f"  - `{key}`: {count}")
    lines.append("- snapshot state density:")
    for key, count in snapshot_counts.most_common(top_n):
        lines.append(f"  - state `{key}`: {count}")
    lines.append("")

    bonus = summary.get("bonus") or {}
    lines.append("## Bonus/HUD")
    for key, count in Counter(bonus.get("bonus_apply_id_counts") or {}).most_common(top_n):
        lines.append(f"- bonus id `{key}`: {count}")
    for key, count in Counter(bonus.get("bonus_hud_timer_ptr_counts") or {}).most_common(top_n):
        lines.append(f"- timer ptr: `{key}` x{count}")
    lines.append("")

    wp = summary.get("weapon_and_projectile") or {}
    lines.append("## Weapon/projectile")
    for key, count in Counter(wp.get("weapon_assign_counts") or {}).most_common(top_n):
        lines.append(f"- weapon assign `{key}`: {count}")
    lines.append(
        f"- projectile overrides: true={wp.get('projectile_override_true', 0)} false={wp.get('projectile_override_false', 0)}"
    )
    for key, count in Counter(wp.get("projectile_type_pairs") or {}).most_common(top_n):
        lines.append(f"- projectile type pair `{key}`: {count}")
    lines.append("")

    qr = summary.get("quest_results") or {}
    lines.append("## Quest results reveal")
    lines.append(f"- samples: {qr.get('samples', 0)}")
    lines.append(f"- final_time_ms min/max: {qr.get('final_time_ms_min')} / {qr.get('final_time_ms_max')}")
    for key, count in Counter(qr.get("unlock_weapon_counts") or {}).most_common(top_n):
        lines.append(f"- unlock weapon id `{key}`: {count}")
    for key, count in Counter(qr.get("unlock_perk_counts") or {}).most_common(top_n):
        lines.append(f"- unlock perk id `{key}`: {count}")
    lines.append("")

    ui = summary.get("ui_subtemplate") or {}
    lines.append("## UI subtemplate deltas")
    lines.append("- top offset writes:")
    for row in ui.get("top_offset_changes") or []:
        lines.append(f"  - {row.get('key')}: {row.get('count')}")
    lines.append("- decoded field changes:")
    for row in ui.get("top_field_changes") or []:
        lines.append(f"  - {row.get('key')}: {row.get('count')}")
    lines.append("")

    sfx = summary.get("sfx") or {}
    lines.append("## SFX by function")
    for row in sfx.get("top_by_function") or []:
        lines.append(f"- {row.get('key')}: {row.get('count')}")
    lines.append("- top function+id pairs:")
    for row in sfx.get("top_by_function_and_id") or []:
        lines.append(f"  - {row.get('key')}: {row.get('count')}")
    lines.append("- high-confidence function->id:")
    for row in sfx.get("high_confidence_function_ids") or []:
        sid = row.get("id")
        sid_text = "None" if sid is None else str(sid)
        share = row.get("share")
        share_text = f"{float(share) * 100:.1f}%" if isinstance(share, (int, float)) else str(share)
        lines.append(
            f"  - {row.get('event')}|{row.get('function')} -> id {sid_text} "
            f"({row.get('count')}/{row.get('total')}, {share_text})"
        )
    lines.append("")

    mem_watch = summary.get("mem_watch") or {}
    lines.append("## Memory watch")
    lines.append(f"- mem_watch_access events: {mem_watch.get('access_count', 0)}")
    for key, count in Counter(mem_watch.get("range_counts") or {}).most_common(top_n):
        lines.append(f"- range `{key}`: {count}")
    lines.append("")

    typing = summary.get("typing_artifacts") or {}
    lines.append("## Type artifact checks")
    lines.append(
        f"- clip_size bit-pattern samples: {typing.get('clip_bitpattern_samples', 0)} / {typing.get('clip_samples', 0)}"
    )
    lines.append(
        f"- ammo bit-pattern samples: {typing.get('ammo_bitpattern_samples', 0)} / {typing.get('ammo_samples', 0)}"
    )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Reduce gameplay_state_capture.jsonl into a compact analysis summary.")
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("artifacts/frida/share/gameplay_state_capture.jsonl"),
        help="input JSONL log",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("analysis/frida/gameplay_state_capture_summary.json"),
        help="output summary JSON path",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("analysis/frida/gameplay_state_capture_report.md"),
        help="output markdown report path",
    )
    parser.add_argument(
        "--sfx-candidates",
        type=Path,
        default=Path("analysis/frida/gameplay_state_capture_sfx_candidates.json"),
        help="output JSON path for high-confidence SFX function->id candidates",
    )
    parser.add_argument(
        "--data-map",
        type=Path,
        default=Path("analysis/ghidra/maps/data_map.json"),
        help="data_map.json for symbolization",
    )
    parser.add_argument(
        "--function-map",
        type=Path,
        default=Path("analysis/ghidra/raw/crimsonland.exe_functions.json"),
        help="function map for caller symbolization",
    )
    parser.add_argument("--top", type=int, default=30, help="top-N rows for report tables")
    args = parser.parse_args()

    if not args.log.exists():
        raise SystemExit(f"log not found: {args.log}")
    if not args.data_map.exists():
        raise SystemExit(f"data map not found: {args.data_map}")
    if not args.function_map.exists():
        raise SystemExit(f"function map not found: {args.function_map}")

    symbols = SymbolIndex(args.data_map)
    functions = FunctionIndex(args.function_map)
    summary = summarize(args.log, symbols, functions, args.top)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.sfx_candidates.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.report.write_text(build_report(summary, args.top), encoding="utf-8")
    sfx_candidates = (summary.get("sfx") or {}).get("high_confidence_function_ids") or []
    args.sfx_candidates.write_text(json.dumps(sfx_candidates, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"wrote {args.out}")
    print(f"wrote {args.report}")
    print(f"wrote {args.sfx_candidates}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
