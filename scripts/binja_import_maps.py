"""
Binary Ninja script to apply our Ghidra maps (name_map/data_map).

Usage:
  - In Binary Ninja: open the binary and run this script (Tools -> Run Script).
  - Or from the console: import binja_import_maps as m; m.apply_maps(bv)

Name-map rows may include ``local_types`` entries keyed by the address of an
instruction that defines an SSA variable. Ambiguous addresses may select the
original variable with ``source_name``. This preserves narrow presentation
annotations when Binary Ninja loses a recovered pointee type across a
compiler-generated reload.

Large recovered functions may also set ``analysis_skip_override`` to
``never_skip``. This makes Binary Ninja retain their LLIL, MLIL, and HLIL even
when the default analysis-time heuristic would otherwise discard them.

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


_SEEDED_TYPES = False
_SEEDED_REPO_HEADERS = False

_AUTHORITATIVE_REPO_TYPES = frozenset(
    {
        # The importer previously synthesized FILE as a one-byte opaque
        # structure before the bundled CRT layout was recovered.
        "FILE",
        # The original database kept the projectile record's interior-cursor
        # view as its primary layout, which rendered ordinary accesses as
        # pos.tail.vy.*. Prefer the equivalent flat Binary Ninja view.
        "projectile_t",
        "projectile_pool_t",
        # Particle render styles reinterpret the four-float scale block as
        # RGBA, intensity as progress, and spin as rotation.
        "particle_t",
        "particle_binja_t",
        # The FX constructor carries interior cursors through vector and color
        # aggregates; use a flat view for readable induction-variable HLIL.
        "fx_queue_entry_t",
        "fx_queue_entry_binja_t",
        # The database's older creature layout typed phase_seed as float even
        # though allocation stores masked rand() integers and AI converts the
        # member to float explicitly before using it as an orbit phase.
        "creature_t",
        "creature_binja_t",
        "creature_lifecycle_stride_binja_t",
        "creature_max_health_stride_binja_t",
        # Creature metadata still carried an older field_0x20 member in the
        # database after the write-only slot was characterized.
        "creature_type_t",
        "creature_type_table_t",
        # The status initializer writes the reserved tail as four independent
        # random dwords; retain both that word view and the raw byte span.
        "game_status_t",
        # The older database treated the random tag at 0x38 as part of an
        # eight-byte reserved span. Record construction, packing, checksums,
        # and the standalone data symbol prove a uint32_t random_tag followed
        # by only four reserved bytes.
        "highscore_record_t",
        # Both 0x40-byte persisted binding spans are complete per-player
        # records, not 13 keys followed by unrelated padding.
        "player_input_config_t",
        "crimson_cfg_t",
        # The construction base precedes the shifted public weapon_stats_t view
        # by one dword and owns the ammo class at the start of every row.
        "weapon_storage_entry_t",
        "weapon_storage_table_t",
        # Use the equivalent flat parameters view so onPause and request_exit
        # survive anonymous-union lowering as named fields.
        "mod_interface_t",
        # Quest builders write an array through their first-element pointer.
        # Keep both the element and table presentation layouts authoritative.
        "quest_spawn_entry_next_block_t",
        "quest_spawn_entry_position_block_t",
        "quest_spawn_entry_trigger_cursor_t",
        "quest_spawn_entry_template_cursor_t",
        "quest_spawn_entry_t",
        "quest_spawn_pair_binja_t",
        "quest_spawn_entries_binja_t",
        # This layout is shared by three ui_element_t rendering layers. Keep
        # the recovered z/rhw/color/u/v members in sync with the canonical
        # header instead of preserving older field_0xNN database members.
        "ui_element_vertex_t",
        "ui_element_vertex_binja_t",
        "ui_element_t",
        "ui_element_binja_t",
        "ui_menu_item_subtemplate_slot_t",
        "ui_menu_item_subtemplate_slot_binja_t",
        # HUD reset loops carry an interior slide cursor. Keep the canonical
        # compiler shape while presenting one flat owning record in HLIL.
        "bonus_hud_slot_t",
        "bonus_hud_slot_table_t",
        "bonus_hud_slot_binja_t",
    },
)

_REPO_TYPE_VIEW_OVERRIDES = {
    "mod_interface_t": "mod_interface_binja_t",
    # Keep the cursor-oriented compiler view in the matching header, but give
    # Binary Ninja the equivalent flat record so ordinary IL uses field names.
    "projectile_t": "projectile_binja_t",
    "creature_t": "creature_binja_t",
    "particle_t": "particle_binja_t",
    "fx_queue_entry_t": "fx_queue_entry_binja_t",
    "ui_element_vertex_t": "ui_element_vertex_binja_t",
    "ui_element_t": "ui_element_binja_t",
    "ui_menu_item_subtemplate_slot_t": (
        "ui_menu_item_subtemplate_slot_binja_t"
    ),
    "bonus_hud_slot_t": "bonus_hud_slot_binja_t",
}

_REPO_TYPE_ARRAY_VIEW_OVERRIDES = {
    "projectile_pool_t": ("projectile_binja_t", 0x60),
    "bonus_hud_slot_table_t": ("bonus_hud_slot_binja_t", 0x10),
}

# Pointer arrays are not aggregate records for general importer overlap
# purposes: data maps may intentionally name and type their individual slots.
# This recovered table is the exception. Preserve its full array data variable
# while still applying the 41 interior symbols and comments.
_FORCED_DATA_AGGREGATES = frozenset(
    {
        "ui_element_table_end",
    },
)

# These builders advance an entry cursor through a loop. Keeping the canonical
# element-pointer signature gives Binary Ninja the correct 0x18 pointer stride;
# the table wrapper is reserved for builders dominated by fixed-index stores.
_QUEST_CURSOR_BUILDERS = frozenset(
    {
        "quest_build_arachnoid_farm",
        "quest_build_deja_vu",
        "quest_build_everred_pastures",
        "quest_build_evil_zombies_at_large",
        "quest_build_frontline_assault",
        "quest_build_gauntlet",
        "quest_build_nagolipoli",
        "quest_build_surrounded_by_reptiles",
        "quest_build_survival_of_the_fastest",
        "quest_build_sweep_stakes",
        "quest_build_target_practice",
        "quest_build_the_killing",
        "quest_build_the_massacre",
        "quest_build_the_unblitzkrieg",
        "quest_build_two_fronts",
    },
)

_TYPE_REPLACEMENTS = {
    "IGrim2D": "void",
    "LPDIRECT3D8": "void *",
    "LPDIRECT3DDEVICE8": "void *",
    "LPDIRECT3DSURFACE8": "void *",
    "LPDIRECTSOUNDBUFFER": "void *",
    "OggVorbis_File": "void",
    "ogg_int64_t": "long long",
    "ov_callbacks": "void *",
    "png_bytep": "unsigned char *",
    "png_structp": "void *",
    "png_voidp": "void *",
    "png_uint_32": "unsigned int",
    "uInt": "unsigned int",
    "uLong": "unsigned long",
    "uLongf": "unsigned long",
    "ulonglong": "unsigned long long",
    "uint": "unsigned int",
    "undefined1": "unsigned char",
    "undefined4": "unsigned int",
    "voidp": "void *",
    "voidpf": "void *",
    "vorbis_info": "void",
    "z_streamp": "void *",
}


def _log_info(message: str) -> None:
    if bn is not None:
        bn.log_info(message)
    else:
        print(message)


def _log_error(message: str) -> None:
    if bn is not None:
        bn.log_error(message)
    else:
        print(f"error: {message}")


def _require_platform(bv):
    platform = bv.platform
    if platform is None:
        raise RuntimeError("BinaryView has no platform")
    return platform


def _candidate_roots(bv=None) -> list[Path]:
    bases: list[Path] = []
    if bv is not None:
        for value in (bv.file.original_filename, bv.file.filename):
            if value:
                try:
                    bases.append(Path(value).resolve().parent)
                except Exception:
                    pass
    if "__file__" in globals():
        try:
            script_path = Path(__file__).resolve()
            bases.append(script_path.parent)
            if len(script_path.parents) >= 2:
                bases.append(script_path.parents[1])
        except Exception:
            pass
    try:
        bases.append(Path.cwd())
    except Exception:
        pass

    roots: list[Path] = []
    for base in bases:
        for candidate in (base, *base.parents):
            if candidate not in roots:
                roots.append(candidate)
    return roots


def _find_repo_root(bv=None) -> Path | None:
    for root in _candidate_roots(bv):
        if (root / "analysis" / "ghidra" / "maps").is_dir():
            return root
    return None


def _default_map_path(env_var: str, rel_path: str, bv=None) -> Path | None:
    env_value = os.getenv(env_var, "").strip()
    if env_value:
        return Path(env_value).expanduser()
    repo_root = _find_repo_root(bv)
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
    for value in (bv.file.original_filename, bv.file.filename):
        if value:
            for item in (str(value), os.path.basename(str(value))):
                lowered = item.lower()
                candidates.add(lowered)
                if lowered.endswith(".bndb"):
                    candidates.add(lowered[:-5])
    return candidates


def _program_matches(entry_program: str | None, candidates: set[str]) -> bool:
    if not entry_program:
        return True
    return entry_program.lower() in candidates


def _parse_type_string(bv, type_text: str):
    parsed_type, _ = bv.parse_type_string(type_text)
    return parsed_type


def _get_type_by_name(bv, name: str):
    return bv.get_type_by_name(name)


def _define_user_type(bv, name: str, type_obj) -> bool:
    if bn is None or type_obj is None:
        return False
    try:
        bv.define_user_type(name, type_obj)
        return True
    except Exception:
        return False


def _undefine_user_type(bv, name) -> bool:
    try:
        bv.undefine_user_type(name)
        return True
    except Exception:
        return False


def _define_or_replace_user_type(bv, name, type_obj) -> bool:
    if _get_type_by_name(bv, name) is not None:
        if not _undefine_user_type(bv, name):
            return False
    return _define_user_type(bv, name, type_obj)


def _define_alias_type(bv, name: str, type_obj) -> bool:
    if _get_type_by_name(bv, name) is not None:
        return True
    return _define_user_type(bv, name, type_obj)


def _type_uint(bits: int):
    if bn is None:
        return None
    return bn.Type.int(bits // 8, False)


def _type_sint(bits: int):
    if bn is None:
        return None
    return bn.Type.int(bits // 8, True)


def _type_width(type_obj) -> int | None:
    if type_obj is None:
        return None
    return type_obj.width


def _type_member_count(type_obj) -> int | None:
    if type_obj is None:
        return None
    if type_obj.type_class != bn.TypeClass.StructureTypeClass:
        return None
    return len(type_obj.members)


def _should_replace_incomplete_type(existing, replacement) -> bool:
    existing_members = _type_member_count(existing)
    replacement_members = _type_member_count(replacement)
    if replacement_members in (None, 0) or existing_members not in (0, None):
        return False
    existing_width = _type_width(existing)
    replacement_width = _type_width(replacement)
    return (
        existing_width is None
        or replacement_width is None
        or existing_width == replacement_width
    )


def _should_replace_repo_type(name: str, existing, replacement) -> bool:
    return name in _AUTHORITATIVE_REPO_TYPES or _should_replace_incomplete_type(
        existing,
        replacement,
    )


def _define_opaque_struct_type(bv, name: str, size: int | None = None) -> bool:
    existing = _get_type_by_name(bv, name)
    if existing is not None:
        width = _type_width(existing)
        if width is None or width > 0:
            return True
    if bn is None:
        return False

    if size is None:
        # Clang treats empty structs as 1 byte; Binja's 0-byte structs cause noisy conversion warnings.
        size = 1

    sb = bn.StructureBuilder.create(width=int(size))
    struct_type = bn.Type.structure_type(sb)
    if existing is not None:
        return _define_or_replace_user_type(bv, name, struct_type)
    return _define_user_type(bv, name, struct_type)


def _parse_types_from_source(bv, source: str, *, filename: str | None = None, include_dirs: list[str] | None = None):
    if not filename:
        raise ValueError("filename is required for type source parsing")

    return bv.platform.parse_types_from_source(
        source,
        filename=filename,
        include_dirs=include_dirs or [],
        auto_type_source="user",
    )


def _extract_parsed_types(parsed) -> dict:
    if parsed is None:
        raise RuntimeError("type parser returned no result")
    types = parsed.types
    if not isinstance(types, dict):
        raise TypeError(f"unexpected parsed type container: {type(parsed)!r}")
    return types


def _sanitize_header_source(source: str) -> str:
    if not source:
        return source
    return "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))


def _header_parse_prelude(source: str) -> str:
    import re

    if not source:
        return ""

    prelude: list[str] = []
    for name, replacement in sorted(_TYPE_REPLACEMENTS.items()):
        typedef_def = rf"\btypedef\b[^;\n{{}}]*\b{re.escape(name)}\b\s*(?:;|\[|\()"
        tag_def = rf"\b(?:struct|union|enum)\s+{re.escape(name)}\b\s*(?:;|\{{)"
        if re.search(typedef_def, source) or re.search(tag_def, source):
            continue
        prelude.append(f"typedef {replacement} {name};")
    if not prelude:
        return ""
    return "\n".join(prelude) + "\n"


def _seed_repo_headers(bv) -> None:
    global _SEEDED_REPO_HEADERS
    if _SEEDED_REPO_HEADERS or not bn:
        return

    env_value = os.getenv("CRIMSON_BINJA_SEED_HEADERS", "").strip().lower()
    if env_value in {"0", "false", "no", "off"}:
        _SEEDED_REPO_HEADERS = True
        return

    header_list = os.getenv("CRIMSON_BINJA_TYPE_HEADERS", "").strip()
    header_paths: list[Path] = []
    if header_list:
        for item in header_list.split(os.pathsep):
            item = item.strip()
            if not item:
                continue
            header_paths.append(Path(item).expanduser())
    else:
        repo_root = _find_repo_root(bv)
        if repo_root is not None:
            header_paths.extend(
                [
                    repo_root / "third_party" / "headers" / "crimsonland_ida_types.h",
                    repo_root / "third_party" / "headers" / "crimsonland_types.h",
                    repo_root / "tools" / "match" / "include" / "crimsonland_console.h",
                    repo_root / "tools" / "match" / "include" / "crimsonland_metadata.h",
                ],
            )

    include_dirs = []
    repo_root = _find_repo_root(bv)
    if repo_root is not None:
        include_dirs.append(str(repo_root / "third_party" / "headers"))
        include_dirs.append(str(repo_root / "tools" / "match" / "include"))

    seeded_total = 0
    for header_path in header_paths:
        if not header_path.exists():
            raise FileNotFoundError(f"type header not found: {header_path}")
        source = header_path.read_text(encoding="utf-8", errors="replace")

        source = _sanitize_header_source(source)
        parsed_source = _header_parse_prelude(source) + source
        parsed = _parse_types_from_source(bv, parsed_source, filename=str(header_path), include_dirs=include_dirs)
        types = _extract_parsed_types(parsed)
        if not types:
            raise RuntimeError(f"type header parsed zero types: {header_path}")

        for name, type_obj in types.items():
            name_str = str(name)
            if not name_str:
                raise RuntimeError(f"type header produced unnamed type in {header_path}")
            view_name = _REPO_TYPE_VIEW_OVERRIDES.get(name_str)
            if view_name is not None:
                type_obj = types.get(view_name)
                if type_obj is None:
                    raise RuntimeError(
                        f"missing Binary Ninja view {view_name} for {name_str}",
                    )
            array_view = _REPO_TYPE_ARRAY_VIEW_OVERRIDES.get(name_str)
            if array_view is not None:
                view_name, count = array_view
                element_type = types.get(view_name)
                if element_type is None:
                    raise RuntimeError(
                        f"missing Binary Ninja view {view_name} for {name_str}",
                    )
                type_obj = bn.Type.array(element_type, count)
            existing = _get_type_by_name(bv, name_str)
            if existing is not None:
                if not _should_replace_repo_type(name_str, existing, type_obj):
                    continue
            if not _define_or_replace_user_type(bv, name, type_obj):
                raise RuntimeError(f"failed to define type {name_str} from {header_path}")
            seeded_total += 1

    if seeded_total:
        _log_info(f"Seeded {seeded_total} typedef(s)/struct(s) from repo headers")

    _SEEDED_REPO_HEADERS = True


def _seed_common_types(bv) -> None:
    global _SEEDED_TYPES
    if _SEEDED_TYPES or bn is None:
        return

    _seed_repo_headers(bv)

    # C++ matching views that have the same object layout as their canonical
    # C records. Keep the class-facing names available to curated signatures
    # without parsing the dependency-heavy compiler harness headers.
    for alias, target in (("sfx_entry_cpp_t", "sfx_entry_t"),):
        target_type = _get_type_by_name(bv, target)
        if target_type is None:
            raise RuntimeError(f"missing canonical type {target} for alias {alias}")
        if not _define_alias_type(bv, alias, target_type):
            raise RuntimeError(f"failed to define layout alias type {alias}")

    # Numeric typedefs that commonly appear in Ghidra-derived signatures.
    for name, type_obj in (
        ("uint", _type_uint(32)),
        ("ushort", _type_uint(16)),
        ("uchar", _type_uint(8)),
        ("uInt", _type_uint(32)),
        ("uLong", _type_uint(32)),
        ("ulonglong", _type_uint(64)),
        ("byte", _type_uint(8)),
        ("undefined1", _type_uint(8)),
        ("undefined2", _type_uint(16)),
        ("undefined4", _type_uint(32)),
        ("undefined8", _type_uint(64)),
    ):
        if not _define_alias_type(bv, name, type_obj):
            raise RuntimeError(f"failed to define common alias type {name}")

    # Common size types.
    addr_bytes = bv.arch.address_size
    if addr_bytes in (4, 8):
        for name, type_obj in (
            ("size_t", _type_uint(addr_bytes * 8)),
            ("ssize_t", _type_sint(addr_bytes * 8)),
            ("uintptr_t", _type_uint(addr_bytes * 8)),
            ("intptr_t", _type_sint(addr_bytes * 8)),
        ):
            if not _define_alias_type(bv, name, type_obj):
                raise RuntimeError(f"failed to define common alias type {name}")

    # Opaque structs frequently used in signatures as pointer bases.
    if not _define_opaque_struct_type(bv, "FILE"):
        raise RuntimeError("failed to define FILE opaque struct")

    _SEEDED_TYPES = True


def _type_keywords() -> set[str]:
    return {
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "signed",
        "unsigned",
        "const",
        "volatile",
        "struct",
        "union",
        "enum",
        "bool",
        "_Bool",
        "restrict",
        "register",
        "static",
        "extern",
        "inline",
        "__int8",
        "__int16",
        "__int32",
        "__int64",
        "__cdecl",
        "__stdcall",
        "__fastcall",
        "__thiscall",
        "__vectorcall",
        "__ptr64",
        "__ptr32",
        "__unaligned",
        "__restrict",
        "__w64",
        "far",
        "near",
    }


def _rewrite_type_tokens(text: str, bv=None) -> str:
    import re

    if not text:
        return text
    parts = re.split(r"([A-Za-z_][A-Za-z0-9_]*)", text)
    for idx in range(1, len(parts), 2):
        token = parts[idx]
        if bv is not None and _get_type_by_name(bv, token) is not None:
            continue
        replacement = _TYPE_REPLACEMENTS.get(token)
        if replacement:
            parts[idx] = replacement
    return "".join(parts)


def _sanitize_signature(signature: str, bv=None) -> str:
    # Ghidra-derived signatures sometimes use C++ keywords for parameter names (e.g. `this`).
    # Binja's parser may treat these as reserved depending on the language mode.
    import re

    signature = re.sub(r"\bthis\b", "self", signature)
    return _rewrite_type_tokens(signature, bv)


def _presentation_signature(name: str, signature: str) -> str:
    """Use layout-equivalent types that produce clearer Binary Ninja IL."""
    if not name.startswith("quest_build_") or name in _QUEST_CURSOR_BUILDERS:
        return signature

    import re

    return re.sub(
        r"\bquest_spawn_entry_t\s*\*\s*entries\b",
        "quest_spawn_entries_binja_t *table",
        signature,
        count=1,
    )


def _split_params(param_text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for idx, ch in enumerate(param_text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(param_text[start:idx].strip())
            start = idx + 1
    tail = param_text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _strip_param_names(signature: str) -> str:
    import re

    prefix, sep, rest = signature.partition("(")
    if not sep:
        return signature
    params, sep2, suffix = rest.rpartition(")")
    if not sep2:
        return signature

    keywords = _type_keywords()
    new_params: list[str] = []
    for param in _split_params(params):
        p = param.strip()
        if not p or p in {"void", "..."}:
            new_params.append(p)
            continue

        # Remove names from function pointer params: `void (*cmd)(void)` -> `void (*)(void)`
        p = re.sub(r"\(\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\)", "(*)", p)

        ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", p)
        if len(ids) >= 2 and ids[-1] not in keywords:
            if not (len(ids) == 2 and ids[0] in {"struct", "union", "enum"}):
                p = re.sub(rf"\b{re.escape(ids[-1])}\b\s*$", "", p).rstrip()

        new_params.append(p)

    return f"{prefix}({', '.join(new_params)}){suffix}"




def _resolve_data_type(bv, type_text: str):
    _seed_common_types(bv)
    rewritten = _rewrite_type_tokens(type_text, bv)
    if rewritten.isidentifier():
        named_type = _get_type_by_name(bv, rewritten)
        if named_type is not None:
            return named_type
    return _parse_type_string(bv, rewritten)


def _deref_type(bv, type_obj):
    current = type_obj
    while current is not None and current.type_class == bn.TypeClass.NamedTypeReferenceClass:
        current = current.deref_named_type_reference(bv)
    return current


def _is_aggregate_type(bv, type_obj) -> bool:
    current = _deref_type(bv, type_obj)
    if current is None:
        return False
    if current.type_class == bn.TypeClass.StructureTypeClass:
        return True
    if current.type_class != bn.TypeClass.ArrayTypeClass:
        return False
    element_type = getattr(current, "element_type", None)
    if element_type is None:
        return False
    return _is_aggregate_type(bv, element_type)


def _find_enclosing_aggregate_range(
    aggregate_ranges: list[tuple[int, int, str]],
    addr: int,
) -> tuple[int, int, str] | None:
    for start, end, label in reversed(aggregate_ranges):
        if start < addr < end:
            return start, end, label
    return None


def _apply_function_signature(bv, func, signature: str) -> None:
    _seed_common_types(bv)

    signature = _sanitize_signature(signature, bv)
    try:
        func_type = _parse_type_string(bv, signature)
    except Exception as first_exc:
        stripped = _strip_param_names(signature)
        if stripped == signature:
            raise RuntimeError(f"failed to parse function signature {signature!r}") from first_exc
        try:
            func_type = _parse_type_string(bv, stripped)
        except Exception as second_exc:
            raise RuntimeError(
                f"failed to parse function signature {signature!r} even after stripping parameter names",
            ) from second_exc

    func.set_user_type(func_type)


def _written_variable_at(
    func,
    addr: int,
    source_names: frozenset[str] = frozenset(),
):
    """Resolve one SSA variable defined by an instruction address."""
    candidates = []
    for block in func.mlil.ssa_form:
        for instruction in block:
            if instruction.address != addr:
                continue
            for ssa_var in instruction.vars_written:
                var = getattr(ssa_var, "var", ssa_var)
                if var not in candidates:
                    candidates.append(var)

    if source_names:
        candidates = [
            var for var in candidates if var.name in source_names
        ]

    if len(candidates) != 1:
        selector = (
            f" matching {sorted(source_names)!r}" if source_names else ""
        )
        raise LookupError(
            f"expected one written variable at 0x{addr:x}{selector}, "
            f"found {len(candidates)}",
        )
    return candidates[0]


def _apply_function_local_types(bv, func, entries: list[dict]) -> int:
    applied = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise TypeError(f"unsupported local type entry: {entry!r}")
        addr = _parse_address(entry.get("address"))
        if addr is None:
            raise ValueError(f"invalid local type address: {entry!r}")
        type_text = entry.get("type") or ""
        name = entry.get("name") or ""
        if not type_text or not name:
            raise ValueError(f"local type entry needs type and name: {entry!r}")

        source_name = entry.get("source_name") or ""
        source_names = (
            frozenset((source_name, name)) if source_name else frozenset()
        )
        var = _written_variable_at(func, addr, source_names)
        local_type = _resolve_data_type(bv, type_text)
        if (
            func.is_var_user_defined(var)
            and var.name == name
            and str(var.type) == str(local_type)
        ):
            applied += 1
            continue
        func.create_user_var(var, local_type, name)
        applied += 1
    return applied


def _set_function_comment(func, comment: str) -> None:
    func.comment = comment


def _set_data_comment(bv, addr: int, comment: str) -> None:
    bv.set_comment_at(addr, comment)


def _ensure_address_valid(bv, addr: int) -> bool:
    return bv.is_valid_offset(addr)


def _entry_label(row: dict, addr: int | None = None) -> str:
    name = row.get("name") or "<unnamed>"
    if addr is None:
        addr = _parse_address(row.get("address"))
    addr_text = f"0x{addr:x}" if addr is not None else str(row.get("address"))
    return f"{name} @ {addr_text}"


def _update_analysis(bv) -> None:
    bv.update_analysis_and_wait()


def _apply_analysis_skip_override(func, policy: str) -> bool:
    if policy != "never_skip":
        raise ValueError(f"unsupported analysis_skip_override: {policy!r}")

    current = func.analysis_skip_override
    desired = type(current).NeverSkipFunctionAnalysis
    if current == desired:
        return False
    func.analysis_skip_override = desired
    func.reanalyze()
    return True


def _read_instruction_info(bv, func):
    data = bv.read(func.start, func.arch.max_instr_length)
    return func.arch.get_instruction_info(data, func.start)


def _is_direct_jump_wrapper(bv, func, addr: int) -> bool:
    info = _read_instruction_info(bv, func)
    if len(info.branches) != 1:
        return False
    branch = info.branches[0]
    if branch.type != bn.BranchType.UnconditionalBranch or branch.target != addr:
        return False
    entry_block = next((block for block in func.basic_blocks if block.start == func.start), None)
    if entry_block is None or entry_block.end != func.start + info.length:
        return False
    return any(block.start == addr for block in func.basic_blocks)


def _has_only_padding_before(bv, func, addr: int) -> bool:
    if func.start >= addr:
        return False
    prefix = bv.read(func.start, addr - func.start)
    return bool(prefix) and all(byte in (0x90, 0xCC) for byte in prefix)


def _resolve_function_for_name_row(bv, row: dict, addr: int):
    func = bv.get_function_at(addr)
    if func is not None:
        return func, False

    containing = list(bv.get_functions_containing(addr))
    if len(containing) == 1 and _is_direct_jump_wrapper(bv, containing[0], addr):
        bv.create_user_function(addr)
        created = bv.get_function_at(addr)
        if created is None:
            raise RuntimeError(f"failed to create direct-jump target for {_entry_label(row, addr)}")
        return created, True

    if not row.get("create"):
        return None, False

    if not containing:
        bv.create_user_function(addr)
        created = bv.get_function_at(addr)
        if created is None:
            raise RuntimeError(f"failed to create {_entry_label(row, addr)}")
        return created, True

    if len(containing) != 1:
        raise RuntimeError(f"refusing to create {_entry_label(row, addr)} inside multiple existing functions")

    if _has_only_padding_before(bv, containing[0], addr):
        bv.remove_function(containing[0])
        bv.create_user_function(addr)
        created = bv.get_function_at(addr)
        if created is None:
            raise RuntimeError(f"failed to split padding-prefixed function for {_entry_label(row, addr)}")
        return created, True

    raise RuntimeError(f"refusing to create {_entry_label(row, addr)} inside an existing function")


def apply_name_map(bv, map_path: Path | None = None) -> dict[str, int]:
    if map_path is None:
        map_path = _default_map_path("CRIMSON_NAME_MAP", "analysis/ghidra/maps/name_map.json", bv)
    if map_path is None or not map_path.exists():
        raise FileNotFoundError("name map not found; set CRIMSON_NAME_MAP or pass a path")

    rows = _load_entries(map_path)

    candidates = _program_candidates(bv)
    stats = {
        "applied": 0,
        "renamed": 0,
        "signatures": 0,
        "local_types": 0,
        "analysis_overrides": 0,
        "comments": 0,
        "created": 0,
        "missing": 0,
        "skipped": 0,
    }
    pending_local_types = []

    for row in rows:
        if not isinstance(row, dict):
            raise TypeError(f"unsupported name map row: {row!r}")
        program = row.get("program") or ""
        if program and not _program_matches(program, candidates):
            stats["skipped"] += 1
            continue
        addr = _parse_address(row.get("address"))
        if addr is None:
            raise ValueError(f"invalid function address in name map row: {row!r}")
        func, created = _resolve_function_for_name_row(bv, row, addr)
        if created:
            stats["created"] += 1
        if func is None:
            raise LookupError(f"function not found for {_entry_label(row, addr)}")

        changed = False
        name = row.get("name") or ""
        if name and func.name != name:
            try:
                func.name = name
                stats["renamed"] += 1
                changed = True
            except Exception as exc:
                raise RuntimeError(f"rename failed for {_entry_label(row, addr)}") from exc

        signature = _presentation_signature(name, row.get("signature") or "")
        if signature:
            try:
                _apply_function_signature(bv, func, signature)
            except Exception as exc:
                raise RuntimeError(f"signature parse/apply failed for {_entry_label(row, addr)}") from exc
            stats["signatures"] += 1
            changed = True

        comment = row.get("comment") or ""
        if comment:
            try:
                _set_function_comment(func, comment)
            except Exception as exc:
                raise RuntimeError(f"comment apply failed for {_entry_label(row, addr)}") from exc
            stats["comments"] += 1
            changed = True

        analysis_policy = row.get("analysis_skip_override") or ""
        if analysis_policy:
            try:
                override_changed = _apply_analysis_skip_override(
                    func,
                    analysis_policy,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"analysis override failed for {_entry_label(row, addr)}",
                ) from exc
            if override_changed:
                stats["analysis_overrides"] += 1
                changed = True

        local_types = row.get("local_types") or []
        if local_types:
            if not isinstance(local_types, list):
                raise TypeError(
                    f"local_types must be a list for {_entry_label(row, addr)}",
                )
            pending_local_types.append((func, local_types, row, addr))
            changed = True

        if changed:
            stats["applied"] += 1

    if stats["applied"]:
        _update_analysis(bv)

    for func, entries, row, addr in pending_local_types:
        try:
            stats["local_types"] += _apply_function_local_types(
                bv,
                func,
                entries,
            )
        except Exception as exc:
            raise RuntimeError(
                f"local type apply failed for {_entry_label(row, addr)}",
            ) from exc

    if stats["local_types"]:
        _update_analysis(bv)

    _log_info(f"Applied name map: {map_path}")
    _log_info(
        "Updated entries: {applied} (renamed {renamed}, signatures {signatures}, "
        "local types {local_types}, analysis overrides {analysis_overrides}, "
        "comments {comments})".format(
            **stats,
        ),
    )
    _log_info("Missing: {missing}, Skipped: {skipped}".format(**stats))
    return stats


def apply_data_map(bv, map_path: Path | None = None) -> dict[str, int]:
    if map_path is None:
        map_path = _default_map_path("CRIMSON_DATA_MAP", "analysis/ghidra/maps/data_map.json", bv)
    if map_path is None or not map_path.exists():
        raise FileNotFoundError("data map not found; set CRIMSON_DATA_MAP or pass a path")

    rows = _load_entries(map_path)

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
    aggregate_ranges: list[tuple[int, int, str]] = []

    for row in rows:
        if not isinstance(row, dict):
            raise TypeError(f"unsupported data map row: {row!r}")
        program = row.get("program") or ""
        if program and not _program_matches(program, candidates):
            stats["skipped"] += 1
            continue
        addr = _parse_address(row.get("address"))
        if addr is None:
            raise ValueError(f"invalid data address in data map row: {row!r}")
        if not _ensure_address_valid(bv, addr):
            raise LookupError(f"invalid data address for {_entry_label(row, addr)}")

        changed = False
        name = row.get("name") or ""
        if name:
            existing = bv.get_symbol_at(addr)

            if existing is None:
                try:
                    symbol = bn.Symbol(bn.SymbolType.DataSymbol, addr, name)
                    bv.define_user_symbol(symbol)
                    stats["created"] += 1
                    changed = True
                except Exception as exc:
                    raise RuntimeError(f"create label failed for {_entry_label(row, addr)}") from exc
            elif existing.name != name:
                try:
                    symbol = bn.Symbol(bn.SymbolType.DataSymbol, addr, name)
                    bv.define_user_symbol(symbol)
                    stats["renamed"] += 1
                    changed = True
                except Exception as exc:
                    raise RuntimeError(f"rename label failed for {_entry_label(row, addr)}") from exc

        comment = row.get("comment") or ""
        if comment:
            try:
                _set_data_comment(bv, addr, comment)
            except Exception as exc:
                raise RuntimeError(f"comment apply failed for {_entry_label(row, addr)}") from exc
            stats["comments"] += 1
            changed = True

        type_text = row.get("type") or ""
        if type_text:
            try:
                data_type = _resolve_data_type(bv, type_text)
            except Exception as exc:
                raise RuntimeError(f"type resolution failed for {_entry_label(row, addr)} ({type_text})") from exc
            enclosing = _find_enclosing_aggregate_range(aggregate_ranges, addr)
            if enclosing is None:
                try:
                    bv.define_user_data_var(addr, data_type)
                    stats["types"] += 1
                    changed = True
                except Exception as exc:
                    raise RuntimeError(f"type apply failed for {_entry_label(row, addr)} ({type_text})") from exc
                if data_type.width > 1 and (
                    name in _FORCED_DATA_AGGREGATES
                    or _is_aggregate_type(bv, data_type)
                ):
                    aggregate_ranges.append((addr, addr + data_type.width, _entry_label(row, addr)))
            elif not changed:
                stats["skipped"] += 1

        if changed:
            stats["applied"] += 1

    if stats["applied"]:
        _update_analysis(bv)

    _log_info(f"Applied data map: {map_path}")
    _log_info(
        "Updated entries: {applied} (created {created}, renamed {renamed}, comments {comments}, types {types})".format(
            **stats,
        ),
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
