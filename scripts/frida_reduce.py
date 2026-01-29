from __future__ import annotations

import argparse
import json
import re
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator


LINK_BASE_EXE = 0x00400000
LINK_BASE_GRIM = 0x10000000

MODULE_OFF_RE = re.compile(r"(?P<module>[A-Za-z0-9_.-]+)\s*[!+]\s*(?P<addr>0x[0-9A-Fa-f]+)")
HEX_RE = re.compile(r"0x[0-9A-Fa-f]+")


@dataclass(frozen=True)
class FunctionEntry:
    start: int
    name: str
    signature: str | None
    address_text: str


class FunctionIndex:
    def __init__(self, entries: Iterable[FunctionEntry]) -> None:
        self.entries = sorted(entries, key=lambda e: e.start)
        self.starts = [entry.start for entry in self.entries]

    def lookup(self, address: int) -> FunctionEntry | None:
        idx = bisect_right(self.starts, address) - 1
        if idx < 0:
            return None
        entry = self.entries[idx]
        if idx + 1 < len(self.entries):
            if address >= self.entries[idx + 1].start:
                return None
        return entry


@dataclass
class SessionInfo:
    exe_base: int | None = None
    exe_size: int | None = None
    grim_base: int | None = None
    grim_size: int | None = None


@dataclass
class Evidence:
    textures: Counter[str] = field(default_factory=Counter)
    sfx_ids: Counter[int] = field(default_factory=Counter)
    grim_calls: Counter[str] = field(default_factory=Counter)
    events: Counter[str] = field(default_factory=Counter)


@dataclass(frozen=True)
class Callsite:
    module: str
    static_addr: int
    offset: int
    raw: str


def parse_address(text: str | int | None) -> int | None:
    if text is None:
        return None
    if isinstance(text, int):
        return text
    value = str(text).strip()
    if not value:
        return None
    if value.startswith(("0x", "0X")):
        return int(value, 16)
    if any(ch in "abcdefABCDEF" for ch in value):
        return int(value, 16)
    if value.isdigit() and len(value) >= 6:
        return int(value, 16)
    return int(value, 10)


def format_hex(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{value:08x}"


def load_functions(path: Path) -> list[FunctionEntry]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        if isinstance(data.get("functions"), list):
            rows = data["functions"]
        elif isinstance(data.get("entries"), list):
            rows = data["entries"]
        else:
            rows = []
    elif isinstance(data, list):
        rows = data
    else:
        rows = []

    entries: list[FunctionEntry] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        addr_text = row.get("address")
        addr = parse_address(addr_text)
        if addr is None:
            continue
        name = row.get("name") or f"FUN_{addr:08x}"
        signature = row.get("signature")
        entries.append(
            FunctionEntry(
                start=addr,
                name=name,
                signature=signature,
                address_text=addr_text or format_hex(addr) or "",
            )
        )
    return entries


def parse_callsite(text: str | None, session: SessionInfo | None) -> Callsite | None:
    if not text:
        return None
    match = MODULE_OFF_RE.search(text)
    if match:
        module = match.group("module")
        value = parse_address(match.group("addr"))
        if value is None:
            return None
        module_lower = module.lower()
        if module_lower == "crimsonland.exe":
            if value < LINK_BASE_EXE:
                offset = value
                static_addr = LINK_BASE_EXE + offset
            else:
                static_addr = value
                offset = value - LINK_BASE_EXE
            return Callsite(module="crimsonland.exe", static_addr=static_addr, offset=offset, raw=text)
        if module_lower == "grim.dll":
            offset = value
            static_addr = LINK_BASE_GRIM + offset
            return Callsite(module="grim.dll", static_addr=static_addr, offset=offset, raw=text)
        return Callsite(module=module_lower, static_addr=value, offset=value, raw=text)

    match = HEX_RE.search(text)
    if not match:
        return None
    value = parse_address(match.group(0))
    if value is None:
        return None

    if session and session.exe_base is not None and session.exe_size is not None:
        if session.exe_base <= value < session.exe_base + session.exe_size:
            offset = value - session.exe_base
            static_addr = LINK_BASE_EXE + offset
            return Callsite(module="crimsonland.exe", static_addr=static_addr, offset=offset, raw=text)

    if session and session.grim_base is not None and session.grim_size is not None:
        if session.grim_base <= value < session.grim_base + session.grim_size:
            offset = value - session.grim_base
            static_addr = LINK_BASE_GRIM + offset
            return Callsite(module="grim.dll", static_addr=static_addr, offset=offset, raw=text)

    if LINK_BASE_EXE <= value < LINK_BASE_EXE + 0x2000000:
        return Callsite(module="crimsonland.exe", static_addr=value, offset=value - LINK_BASE_EXE, raw=text)

    return None


def sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", value.strip().lower())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    if not cleaned:
        return "unknown"
    if cleaned[0].isdigit():
        cleaned = f"tex_{cleaned}"
    return cleaned


def common_prefix(names: list[str]) -> str:
    if not names:
        return ""
    split = [name.split("_") for name in names]
    prefix: list[str] = []
    for parts in zip(*split):
        if all(part == parts[0] for part in parts):
            prefix.append(parts[0])
        else:
            break
    return "_".join(prefix)


def iter_jsonl(path: Path) -> Iterator[dict]:
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


def extract_sfx_id(obj: dict) -> int | None:
    guess = obj.get("sfx_id_guess") or obj.get("arg0")
    if isinstance(guess, dict):
        for key in ("raw_u32", "as_i32", "as_u32"):
            value = guess.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, float):
                return int(value)
    if isinstance(guess, int):
        return guess
    if isinstance(guess, float):
        return int(guess)
    return None


def record_evidence(
    evidence: dict[int, Evidence],
    entry: FunctionEntry | None,
    kind: str,
    value: str | int | None,
) -> None:
    if entry is None:
        return
    bucket = evidence.setdefault(entry.start, Evidence())
    bucket.events[kind] += 1
    if kind == "texture" and isinstance(value, str):
        bucket.textures[value] += 1
    elif kind == "sfx" and isinstance(value, int):
        bucket.sfx_ids[value] += 1
    elif kind == "grim" and isinstance(value, str):
        bucket.grim_calls[value] += 1


def build_comment(bucket: Evidence, top_n: int) -> str:
    parts: list[str] = []
    if bucket.textures:
        textures = ", ".join(f"{name} x{count}" for name, count in bucket.textures.most_common(top_n))
        parts.append(f"textures: {textures}")
    if bucket.sfx_ids:
        sfx = ", ".join(f"{sid} x{count}" for sid, count in bucket.sfx_ids.most_common(top_n))
        parts.append(f"sfx: {sfx}")
    if bucket.grim_calls:
        grim = ", ".join(f"{name} x{count}" for name, count in bucket.grim_calls.most_common(top_n))
        parts.append(f"grim: {grim}")
    if not parts:
        return "Frida evidence: (no categorized events)"
    return "Frida evidence: " + "; ".join(parts)


def suggest_name(entry: FunctionEntry, bucket: Evidence) -> str | None:
    if not entry.name.startswith("FUN_"):
        return None
    if bucket.textures:
        textures = list(bucket.textures.keys())
        if len(textures) == 1:
            return f"load_texture_{sanitize_name(textures[0])}"
        if 1 < len(textures) <= 4:
            prefix = common_prefix([sanitize_name(t) for t in textures])
            if prefix:
                return f"load_textures_{prefix}"
    if bucket.sfx_ids and len(bucket.sfx_ids) == 1:
        sid = next(iter(bucket.sfx_ids.keys()))
        return f"play_sfx_{sid}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Reduce Frida JSONL logs into evidence summaries.")
    parser.add_argument(
        "--log",
        action="append",
        type=Path,
        default=[],
        help="JSONL log paths (repeatable).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("analysis/frida"),
        help="output directory",
    )
    parser.add_argument(
        "--function-map",
        type=Path,
        default=Path("analysis/ghidra/raw/crimsonland.exe_functions.json"),
        help="function map JSON from Ghidra",
    )
    parser.add_argument(
        "--min-count",
        type=int,
        default=5,
        help="minimum evidence count to emit a candidate rename",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="top-N items to include in summaries/comments",
    )
    args = parser.parse_args()

    logs = list(args.log)
    if not logs:
        default_logs = [
            Path("analysis/frida/raw/crimsonland_frida_hits.jsonl"),
            Path("analysis/frida/raw/grim_hits.jsonl"),
        ]
        logs = [path for path in default_logs if path.exists()]
    if not logs:
        raise SystemExit("No logs provided (use --log PATH).")

    functions = load_functions(args.function_map)
    grim_map = Path("analysis/ghidra/raw/grim.dll_functions.json")
    if grim_map.exists() and grim_map != args.function_map:
        functions.extend(load_functions(grim_map))
    index = FunctionIndex(functions)

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    facts_path = out_dir / "facts.jsonl"
    summary_path = out_dir / "evidence_summary.json"
    candidates_path = out_dir / "name_map_candidates.json"
    offsets_path = out_dir / "player_unknown_offsets.json"
    unmapped_path = out_dir / "unmapped_calls.json"

    evidence: dict[int, Evidence] = {}
    unmapped: Counter[str] = Counter()
    player_offsets: dict[int, int] = {}

    sessions: dict[str, SessionInfo] = defaultdict(SessionInfo)

    with facts_path.open("w", encoding="utf-8") as facts_handle:
        for log_path in logs:
            session_default = f"log:{log_path.name}"
            for obj in iter_jsonl(log_path):
                session_id = obj.get("session_id") or session_default
                session = sessions[session_id]

                if obj.get("event") == "startup_summary":
                    exe = obj.get("exe") or {}
                    grim = obj.get("grim") or {}
                    session.exe_base = parse_address(exe.get("base")) or session.exe_base
                    session.exe_size = exe.get("size") or session.exe_size
                    session.grim_base = parse_address(grim.get("base")) or session.grim_base
                    session.grim_size = grim.get("size") or session.grim_size

                if obj.get("type") == "base":
                    module = str(obj.get("module") or "").lower()
                    base = parse_address(obj.get("base"))
                    if module == "crimsonland.exe" and base is not None:
                        session.exe_base = base
                    if module == "grim.dll" and base is not None:
                        session.grim_base = base

                if obj.get("event") == "grim_vtable_hooks_installed":
                    session.grim_base = parse_address(obj.get("grim_base")) or session.grim_base
                    session.grim_size = obj.get("grim_size") or session.grim_size

                event = obj.get("event")
                if event in ("texture_get_or_load", "texture_get_or_load_alt"):
                    callsite = parse_callsite(obj.get("caller"), session)
                    entry = None
                    name = obj.get("name")
                    if callsite and callsite.module in ("crimsonland.exe", "grim.dll"):
                        entry = index.lookup(callsite.static_addr)
                        if entry and isinstance(name, str) and name:
                            record_evidence(evidence, entry, "texture", name)
                        if entry is None:
                            unmapped[str(obj.get("caller") or "unknown")] += 1
                    else:
                        unmapped[str(obj.get("caller") or "unknown")] += 1
                    fact = {
                        "kind": "texture_request",
                        "session_id": session_id,
                        "source": "probe",
                        "name": name,
                        "callsite": obj.get("caller"),
                        "callsite_va": format_hex(callsite.static_addr) if callsite else None,
                        "function": {
                            "name": entry.name if callsite and entry else None,
                            "address": format_hex(entry.start) if callsite and entry else None,
                        },
                    }
                    facts_handle.write(json.dumps(fact) + "\n")
                    continue

                if event in ("sfx_play", "sfx_play_panned", "sfx_play_exclusive"):
                    callsite = parse_callsite(obj.get("caller"), session)
                    sfx_id = extract_sfx_id(obj)
                    entry = None
                    if callsite and callsite.module in ("crimsonland.exe", "grim.dll"):
                        entry = index.lookup(callsite.static_addr)
                        if entry:
                            record_evidence(evidence, entry, "sfx", sfx_id)
                        if entry is None:
                            unmapped[str(obj.get("caller") or "unknown")] += 1
                    else:
                        unmapped[str(obj.get("caller") or "unknown")] += 1
                    fact = {
                        "kind": "sfx_play",
                        "session_id": session_id,
                        "source": "probe",
                        "sfx_id": sfx_id,
                        "callsite": obj.get("caller"),
                        "callsite_va": format_hex(callsite.static_addr) if callsite else None,
                        "function": {
                            "name": entry.name if callsite and entry else None,
                            "address": format_hex(entry.start) if callsite and entry else None,
                        },
                    }
                    facts_handle.write(json.dumps(fact) + "\n")
                    continue

                if (
                    event == "start"
                    and obj.get("t0_ms") is not None
                    and isinstance(obj.get("addrs"), dict)
                    and obj["addrs"].get("demo_mode_start") is not None
                ):
                    fact = {
                        "kind": "demo_idle_threshold_start",
                        "session_id": session_id,
                        "source": "demo_idle_threshold_trace",
                        "t0_ms": obj.get("t0_ms"),
                        "module": obj.get("module"),
                        "config": obj.get("config"),
                        "addrs": obj.get("addrs"),
                    }
                    facts_handle.write(json.dumps(fact) + "\n")
                    continue

                if (
                    event == "ui_ready"
                    and obj.get("dt_since_start_ms") is not None
                    and obj.get("ui_elements_timeline") is not None
                    and obj.get("ui_elements_max_timeline") is not None
                ):
                    fact = {
                        "kind": "demo_idle_threshold_ui_ready",
                        "session_id": session_id,
                        "source": "demo_idle_threshold_trace",
                        "t_ms": obj.get("t_ms"),
                        "dt_since_start_ms": obj.get("dt_since_start_ms"),
                        "ui_elements_timeline": obj.get("ui_elements_timeline"),
                        "ui_elements_max_timeline": obj.get("ui_elements_max_timeline"),
                    }
                    facts_handle.write(json.dumps(fact) + "\n")
                    continue

                if (
                    event == "demo_mode_start"
                    and obj.get("dt_since_start_ms") is not None
                    and ("dt_since_ui_ready_ms" in obj)
                ):
                    fact = {
                        "kind": "demo_idle_threshold_demo_mode_start",
                        "session_id": session_id,
                        "source": "demo_idle_threshold_trace",
                        "t_ms": obj.get("t_ms"),
                        "dt_since_start_ms": obj.get("dt_since_start_ms"),
                        "dt_since_ui_ready_ms": obj.get("dt_since_ui_ready_ms"),
                        "game_state_id": obj.get("game_state_id"),
                        "demo_mode_active": obj.get("demo_mode_active"),
                        "ui_elements_timeline": obj.get("ui_elements_timeline"),
                        "ui_elements_max_timeline": obj.get("ui_elements_max_timeline"),
                    }
                    facts_handle.write(json.dumps(fact) + "\n")
                    continue

                if event == "demo_trial_overlay_render":
                    overlay_entry = index.lookup(0x004047c0)
                    if overlay_entry:
                        record_evidence(evidence, overlay_entry, "event", "demo_trial_overlay_render")
                    fact = {
                        "kind": "demo_trial_overlay_render",
                        "session_id": session_id,
                        "source": "demo_trial_overlay_trace",
                        "t_ms": obj.get("t_ms"),
                        "mode_id": obj.get("mode_id"),
                        "game_state_id": obj.get("game_state_id"),
                        "quest_stage_major": obj.get("quest_stage_major"),
                        "quest_stage_minor": obj.get("quest_stage_minor"),
                        "game_sequence_id_ms": obj.get("game_sequence_id_ms"),
                        "demo_trial_elapsed_ms": obj.get("demo_trial_elapsed_ms"),
                        "remaining_ms": obj.get("remaining_ms"),
                        "tier_locked": obj.get("tier_locked"),
                        "xy": obj.get("xy"),
                        "backtrace": obj.get("backtrace"),
                    }
                    facts_handle.write(json.dumps(fact) + "\n")
                    continue

                if event == "grim_vtbl_call":
                    callsite = parse_callsite(obj.get("caller"), session)
                    entry = None
                    if callsite and callsite.module in ("crimsonland.exe", "grim.dll"):
                        entry = index.lookup(callsite.static_addr)
                        if entry:
                            record_evidence(evidence, entry, "grim", obj.get("name") or "")
                        if entry is None:
                            unmapped[str(obj.get("caller") or "unknown")] += 1
                    else:
                        unmapped[str(obj.get("caller") or "unknown")] += 1
                    fact = {
                        "kind": "grim_vtbl_call",
                        "session_id": session_id,
                        "source": "probe",
                        "name": obj.get("name"),
                        "offset": obj.get("offset_hex") or obj.get("offset"),
                        "callsite": obj.get("caller"),
                        "callsite_va": format_hex(callsite.static_addr) if callsite else None,
                        "function": {
                            "name": entry.name if callsite and entry else None,
                            "address": format_hex(entry.start) if callsite and entry else None,
                        },
                    }
                    facts_handle.write(json.dumps(fact) + "\n")
                    continue

                if obj.get("type") == "call":
                    callsite = parse_callsite(obj.get("callsite"), session)
                    entry = None
                    if callsite and callsite.module in ("crimsonland.exe", "grim.dll"):
                        entry = index.lookup(callsite.static_addr)
                        if entry:
                            record_evidence(evidence, entry, "grim", obj.get("name") or "")
                        if entry is None:
                            unmapped[str(obj.get("callsite") or "unknown")] += 1
                    else:
                        unmapped[str(obj.get("callsite") or "unknown")] += 1
                    fact = {
                        "kind": "grim_call",
                        "session_id": session_id,
                        "source": "grim_hooks",
                        "name": obj.get("name"),
                        "callsite": obj.get("callsite"),
                        "callsite_va": format_hex(callsite.static_addr) if callsite else None,
                        "function": {
                            "name": entry.name if callsite and entry else None,
                            "address": format_hex(entry.start) if callsite and entry else None,
                        },
                    }
                    facts_handle.write(json.dumps(fact) + "\n")
                    continue

                if event == "player_unknown_tracker_report":
                    for item in obj.get("top", []) or []:
                        off = item.get("off")
                        cnt = item.get("cnt")
                        if isinstance(off, int) and isinstance(cnt, int):
                            player_offsets[off] = max(player_offsets.get(off, 0), cnt)

    summary = []
    for addr, bucket in evidence.items():
        entry = index.lookup(addr)
        if entry is None:
            continue
        summary.append(
            {
                "address": format_hex(entry.start),
                "name": entry.name,
                "signature": entry.signature,
                "events": dict(bucket.events),
                "textures": bucket.textures.most_common(args.top),
                "sfx_ids": bucket.sfx_ids.most_common(args.top),
                "grim_calls": bucket.grim_calls.most_common(args.top),
            }
        )
    summary.sort(key=lambda row: sum(row.get("events", {}).values()), reverse=True)

    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    candidates = []
    used_names: set[str] = set()
    for addr, bucket in evidence.items():
        entry = index.lookup(addr)
        if entry is None:
            continue
        total = sum(bucket.events.values())
        if total < args.min_count:
            continue
        suggestion = suggest_name(entry, bucket)
        if not suggestion:
            continue
        name = suggestion
        if name in used_names:
            name = f"{name}_at_{entry.start:08x}"
        used_names.add(name)
        candidates.append(
            {
                "program": "crimsonland.exe",
                "address": format_hex(entry.start),
                "name": name,
                "comment": build_comment(bucket, args.top),
            }
        )
    candidates_path.write_text(json.dumps(candidates, indent=2) + "\n", encoding="utf-8")

    if player_offsets:
        offsets = [
            {"offset": off, "offset_hex": f"0x{off:03x}", "count": cnt}
            for off, cnt in sorted(player_offsets.items(), key=lambda item: item[1], reverse=True)
        ]
        offsets_path.write_text(json.dumps(offsets, indent=2) + "\n", encoding="utf-8")

    unmapped_payload = [{"callsite": key, "count": count} for key, count in unmapped.most_common()]
    unmapped_path.write_text(json.dumps(unmapped_payload, indent=2) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
