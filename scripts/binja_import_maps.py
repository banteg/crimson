"""
Binary Ninja script to apply our Ghidra maps (name_map/data_map).

Usage:
  - In Binary Ninja: open the binary and run this script (Tools -> Run Script).
  - Or from the console: import binja_import_maps as m; m.apply_maps(bv)

Environment overrides:
  - CRIMSON_NAME_MAP: path to name_map.json / .csv
  - CRIMSON_DATA_MAP: path to data_map.json / .csv
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

try:
    import binaryninja as bn
except Exception:  # pragma: no cover - only runs inside Binary Ninja
    bn = None


def _log_info(message: str) -> None:
    if bn and hasattr(bn, "log_info"):
        bn.log_info(message)
    else:
        print(message)


def _log_warn(message: str) -> None:
    if bn and hasattr(bn, "log_warn"):
        bn.log_warn(message)
    else:
        print(f"warning: {message}")


def _log_error(message: str) -> None:
    if bn and hasattr(bn, "log_error"):
        bn.log_error(message)
    else:
        print(f"error: {message}")


def _candidate_roots() -> list[Path]:
    roots: list[Path] = []
    if "__file__" in globals():
        try:
            script_path = Path(__file__).resolve()
            roots.append(script_path.parent)
            if len(script_path.parents) >= 2:
                roots.append(script_path.parents[1])
        except Exception:
            pass
    try:
        roots.append(Path.cwd())
    except Exception:
        pass
    return roots


def _find_repo_root() -> Path | None:
    for root in _candidate_roots():
        if (root / "analysis" / "ghidra" / "maps").is_dir():
            return root
    return None


def _default_map_path(env_var: str, rel_path: str) -> Path | None:
    env_value = os.getenv(env_var, "").strip()
    if env_value:
        return Path(env_value).expanduser()
    repo_root = _find_repo_root()
    if repo_root:
        return repo_root / rel_path
    return None


def _parse_address(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    base = 10
    if text.lower().startswith("0x"):
        text = text[2:]
        base = 16
    elif any(ch in text for ch in "abcdefABCDEF"):
        base = 16
    try:
        return int(text, base)
    except ValueError:
        return None


def _load_json_entries(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("entries"), list):
            return data["entries"]
        if isinstance(data.get("functions"), list):
            return data["functions"]
    raise ValueError(f"unsupported map format: {path}")


def _load_csv_entries(path: Path) -> list[dict]:
    entries: list[dict] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        header: list[str] | None = None
        for row in reader:
            if not row:
                continue
            if row[0].lstrip().startswith("#"):
                continue
            if header is None:
                header = [item.strip().lower() for item in row]
                continue
            record: dict[str, str] = {}
            for idx, key in enumerate(header):
                record[key] = row[idx].strip() if idx < len(row) else ""
            entries.append(record)
    return entries


def _load_entries(path: Path) -> list[dict]:
    if path.suffix.lower() == ".csv":
        return _load_csv_entries(path)
    return _load_json_entries(path)


def _program_candidates(bv) -> set[str]:
    candidates: set[str] = set()
    if not hasattr(bv, "file"):
        return candidates
    file_obj = bv.file
    for attr in ("original_filename", "filename", "file_name", "path"):
        value = getattr(file_obj, attr, None)
        if not value:
            continue
        candidates.add(str(value).lower())
        candidates.add(os.path.basename(str(value)).lower())
    basename = getattr(file_obj, "basename", None)
    if basename:
        candidates.add(str(basename).lower())
    return candidates


def _program_matches(entry_program: str | None, candidates: set[str]) -> bool:
    if not entry_program:
        return True
    return entry_program.lower() in candidates


def _parse_type_string(bv, type_text: str):
    try:
        return bv.parse_type_string(type_text)
    except Exception:
        pass
    if bn and hasattr(bn, "parse_type_string"):
        try:
            return bn.parse_type_string(type_text)
        except Exception:
            pass
    return None


def _resolve_data_type(bv, type_text: str):
    parsed = _parse_type_string(bv, type_text)
    if parsed is not None:
        if isinstance(parsed, tuple):
            return parsed[0]
        return parsed
    if hasattr(bv, "get_type_by_name"):
        try:
            return bv.get_type_by_name(type_text)
        except Exception:
            return None
    types = getattr(bv, "types", None)
    if isinstance(types, dict):
        return types.get(type_text)
    return None


def _apply_function_signature(bv, func, signature: str) -> bool:
    parsed = _parse_type_string(bv, signature)
    if parsed is None:
        return False
    func_type = parsed[0] if isinstance(parsed, tuple) else parsed
    try:
        if hasattr(func, "set_user_type"):
            func.set_user_type(func_type)
        elif hasattr(func, "function_type"):
            func.function_type = func_type
        elif hasattr(func, "type"):
            func.type = func_type
        else:
            return False
        return True
    except Exception:
        return False


def _set_function_comment(func, comment: str) -> bool:
    try:
        if hasattr(func, "comment"):
            func.comment = comment
            return True
        if hasattr(func, "set_comment"):
            func.set_comment(comment)
            return True
        if hasattr(func, "set_comment_at"):
            func.set_comment_at(func.start, comment)
            return True
    except Exception:
        return False
    return False


def _set_data_comment(bv, addr: int, comment: str) -> bool:
    try:
        if hasattr(bv, "set_comment_at"):
            bv.set_comment_at(addr, comment)
            return True
    except Exception:
        return False
    return False


def _ensure_address_valid(bv, addr: int) -> bool:
    if hasattr(bv, "is_valid_address"):
        return bool(bv.is_valid_address(addr))
    if hasattr(bv, "is_valid_offset"):
        return bool(bv.is_valid_offset(addr))
    if hasattr(bv, "get_segment_at"):
        return bv.get_segment_at(addr) is not None
    return True


def apply_name_map(bv, map_path: Path | None = None) -> dict[str, int]:
    if map_path is None:
        map_path = _default_map_path("CRIMSON_NAME_MAP", "analysis/ghidra/maps/name_map.json")
    if map_path is None or not map_path.exists():
        _log_error("name map not found; set CRIMSON_NAME_MAP or pass a path")
        return {}

    try:
        rows = _load_entries(map_path)
    except Exception as exc:
        _log_error(f"failed to read name map: {exc}")
        return {}

    candidates = _program_candidates(bv)
    stats = {
        "applied": 0,
        "renamed": 0,
        "signatures": 0,
        "comments": 0,
        "created": 0,
        "missing": 0,
        "skipped": 0,
    }

    for row in rows:
        if not isinstance(row, dict):
            continue
        program = row.get("program") or ""
        if program and not _program_matches(program, candidates):
            stats["skipped"] += 1
            continue
        addr = _parse_address(row.get("address"))
        if addr is None:
            continue
        func = bv.get_function_at(addr)
        if func is None and row.get("create"):
            containing = []
            if hasattr(bv, "get_functions_containing"):
                containing = list(bv.get_functions_containing(addr))
            if containing:
                stats["missing"] += 1
                continue
            try:
                bv.create_user_function(addr)
                func = bv.get_function_at(addr)
                if func:
                    stats["created"] += 1
            except Exception:
                func = bv.get_function_at(addr)
        if func is None:
            stats["missing"] += 1
            continue

        changed = False
        name = row.get("name") or ""
        if name and getattr(func, "name", None) != name:
            try:
                func.name = name
                stats["renamed"] += 1
                changed = True
            except Exception:
                _log_warn(f"rename failed for {name} at 0x{addr:x}")

        signature = row.get("signature") or ""
        if signature:
            if _apply_function_signature(bv, func, signature):
                stats["signatures"] += 1
                changed = True
            else:
                _log_warn(f"signature parse/apply failed for {name or '0x%08x' % addr}")

        comment = row.get("comment") or ""
        if comment:
            if _set_function_comment(func, comment):
                stats["comments"] += 1
                changed = True

        if changed:
            stats["applied"] += 1

    _log_info(f"Applied name map: {map_path}")
    _log_info(
        "Updated entries: {applied} (renamed {renamed}, signatures {signatures}, comments {comments})".format(
            **stats
        )
    )
    _log_info("Missing: {missing}, Skipped: {skipped}".format(**stats))
    return stats


def apply_data_map(bv, map_path: Path | None = None) -> dict[str, int]:
    if map_path is None:
        map_path = _default_map_path("CRIMSON_DATA_MAP", "analysis/ghidra/maps/data_map.json")
    if map_path is None or not map_path.exists():
        _log_error("data map not found; set CRIMSON_DATA_MAP or pass a path")
        return {}

    try:
        rows = _load_entries(map_path)
    except Exception as exc:
        _log_error(f"failed to read data map: {exc}")
        return {}

    candidates = _program_candidates(bv)
    stats = {
        "applied": 0,
        "created": 0,
        "renamed": 0,
        "comments": 0,
        "types": 0,
        "missing": 0,
        "skipped": 0,
    }

    for row in rows:
        if not isinstance(row, dict):
            continue
        program = row.get("program") or ""
        if program and not _program_matches(program, candidates):
            stats["skipped"] += 1
            continue
        addr = _parse_address(row.get("address"))
        if addr is None:
            continue
        if not _ensure_address_valid(bv, addr):
            stats["missing"] += 1
            continue

        changed = False
        name = row.get("name") or ""
        if name:
            existing = None
            if hasattr(bv, "get_symbol_at"):
                existing = bv.get_symbol_at(addr)
            if existing is None and hasattr(bv, "get_symbols_at"):
                symbols = list(bv.get_symbols_at(addr))
                existing = symbols[0] if symbols else None

            if existing is None:
                try:
                    symbol = bn.Symbol(bn.SymbolType.DataSymbol, addr, name)
                    bv.define_user_symbol(symbol)
                    stats["created"] += 1
                    changed = True
                except Exception:
                    _log_warn(f"create label failed for {name} at 0x{addr:x}")
            elif getattr(existing, "name", None) != name:
                try:
                    symbol = bn.Symbol(bn.SymbolType.DataSymbol, addr, name)
                    bv.define_user_symbol(symbol)
                    stats["renamed"] += 1
                    changed = True
                except Exception:
                    _log_warn(f"rename label failed for {name} at 0x{addr:x}")

        comment = row.get("comment") or ""
        if comment:
            if _set_data_comment(bv, addr, comment):
                stats["comments"] += 1
                changed = True

        type_text = row.get("type") or ""
        if type_text:
            data_type = _resolve_data_type(bv, type_text)
            if data_type is not None:
                try:
                    if hasattr(bv, "define_user_data_var"):
                        bv.define_user_data_var(addr, data_type)
                    elif hasattr(bv, "define_data_var"):
                        bv.define_data_var(addr, data_type)
                    stats["types"] += 1
                    changed = True
                except Exception:
                    _log_warn(f"type apply failed for {name or '0x%08x' % addr} ({type_text})")
            else:
                _log_warn(f"type not found for {name or '0x%08x' % addr}: {type_text}")

        if changed:
            stats["applied"] += 1

    _log_info(f"Applied data map: {map_path}")
    _log_info(
        "Updated entries: {applied} (created {created}, renamed {renamed}, comments {comments}, types {types})".format(
            **stats
        )
    )
    _log_info("Missing: {missing}, Skipped: {skipped}".format(**stats))
    return stats


def apply_maps(bv, name_map: Path | None = None, data_map: Path | None = None) -> None:
    apply_name_map(bv, name_map)
    apply_data_map(bv, data_map)


def _auto_run() -> None:
    if bn is None:
        _log_error("binaryninja module not available; run inside Binary Ninja")
        return
    if "bv" not in globals():
        _log_error("no BinaryView found; call apply_maps(bv) from the console")
        return
    apply_maps(globals()["bv"])


if __name__ == "__main__":  # pragma: no cover
    _auto_run()
else:
    if "bv" in globals():
        _auto_run()
