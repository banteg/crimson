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


_SEEDED_TYPES = False
_SEEDED_REPO_HEADERS = False

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


def _require_platform(bv):
    platform = getattr(bv, "platform", None)
    if platform is None:
        raise RuntimeError("BinaryView has no platform")
    return platform


def _require_type_parser():
    if bn is None:
        raise RuntimeError("binaryninja module not available; run inside Binary Ninja")
    type_parser = getattr(getattr(bn, "TypeParser", None), "default", None)
    if type_parser is None:
        raise RuntimeError("Binary Ninja TypeParser.default is unavailable")
    return type_parser


def _format_type_parser_errors(errors) -> str:
    if not errors:
        return "unknown parser error"

    parts: list[str] = []
    for error in errors:
        file_name = getattr(error, "file_name", "<input>")
        line = getattr(error, "line", "?")
        column = getattr(error, "column", "?")
        message = getattr(error, "message", str(error))
        parts.append(f"{file_name}:{line}:{column}: {message}")
    return "; ".join(parts)


def _candidate_roots(bv=None) -> list[Path]:
    roots: list[Path] = []
    if "__file__" in globals():
        try:
            script_path = Path(__file__).resolve()
            roots.append(script_path.parent)
            if len(script_path.parents) >= 2:
                roots.append(script_path.parents[1])
        except Exception:
            pass
    if bv is not None and hasattr(bv, "file"):
        for attr in ("original_filename", "filename", "file_name", "path"):
            value = getattr(bv.file, attr, None)
            if value:
                try:
                    roots.append(Path(str(value)).resolve().parent)
                except Exception:
                    pass
    try:
        roots.append(Path.cwd())
    except Exception:
        pass
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
    if not hasattr(bv, "file"):
        return candidates
    file_obj = bv.file
    for attr in ("original_filename", "filename", "file_name", "path"):
        value = getattr(file_obj, attr, None)
        if not value:
            continue
        for item in (str(value), os.path.basename(str(value))):
            lowered = item.lower()
            candidates.add(lowered)
            if lowered.endswith(".bndb"):
                candidates.add(lowered[:-5])
    basename = getattr(file_obj, "basename", None)
    if basename:
        lowered = str(basename).lower()
        candidates.add(lowered)
        if lowered.endswith(".bndb"):
            candidates.add(lowered[:-5])
    return candidates


def _program_matches(entry_program: str | None, candidates: set[str]) -> bool:
    if not entry_program:
        return True
    return entry_program.lower() in candidates


def _parse_type_string(bv, type_text: str):
    type_parser = _require_type_parser()
    platform = _require_platform(bv)
    parsed, errors = type_parser.parse_type_string(type_text, platform, existing_types=bv)
    if errors:
        raise ValueError(f"failed to parse type string {type_text!r}: {_format_type_parser_errors(errors)}")
    if parsed is None or not isinstance(parsed, tuple) or len(parsed) != 2:
        raise RuntimeError(f"unexpected parse result for type string {type_text!r}: {parsed!r}")
    return parsed[1]


def _get_type_by_name(bv, name: str):
    if hasattr(bv, "get_type_by_name"):
        try:
            return bv.get_type_by_name(name)
        except Exception:
            return None
    types = getattr(bv, "types", None)
    if isinstance(types, dict):
        return types.get(name)
    return None


def _define_user_type(bv, name: str, type_obj) -> bool:
    if not bn or type_obj is None:
        return False
    if hasattr(bv, "define_user_type"):
        try:
            bv.define_user_type(name, type_obj)
            return True
        except Exception:
            return False
    return False


def _undefine_user_type(bv, name) -> bool:
    for attr in ("undefine_user_type", "undefine_type", "remove_user_type"):
        fn = getattr(bv, attr, None)
        if not callable(fn):
            continue
        try:
            fn(name)
            return True
        except Exception:
            continue
    return False


def _define_or_replace_user_type(bv, name, type_obj) -> bool:
    if _define_user_type(bv, name, type_obj):
        return True
    if _undefine_user_type(bv, name):
        return _define_user_type(bv, name, type_obj)
    return False


def _bn_void_ptr_type(bv):
    if not bn:
        return None
    try:
        if hasattr(bn.Type, "void") and hasattr(bn.Type, "pointer"):
            return bn.Type.pointer(bv.arch, bn.Type.void())
    except Exception:
        pass
    return None


def _define_alias_type(bv, name: str, type_obj) -> bool:
    if _get_type_by_name(bv, name) is not None:
        return True
    return _define_user_type(bv, name, type_obj)


def _structure_builder_create():
    if not bn:
        return None
    for candidate in ("StructureBuilder", "structure"):
        builder = getattr(bn, candidate, None)
        if builder is None:
            continue
        create = getattr(builder, "create", None)
        if callable(create):
            try:
                return create()
            except Exception:
                continue
    types_mod = getattr(bn, "types", None)
    if types_mod is not None:
        builder = getattr(types_mod, "StructureBuilder", None)
        if builder is not None and callable(getattr(builder, "create", None)):
            try:
                return builder.create()
            except Exception:
                return None
    return None


def _type_structure(struct_builder):
    if not bn or struct_builder is None:
        return None
    for attr in ("structure_type", "structure"):
        ctor = getattr(bn.Type, attr, None)
        if callable(ctor):
            try:
                return ctor(struct_builder)
            except Exception:
                continue
    return None


def _type_u8():
    if not bn:
        return None
    try:
        return bn.Type.int(1, False)
    except Exception:
        return None


def _type_uint(bits: int):
    if not bn:
        return None
    try:
        return bn.Type.int(bits // 8, False)
    except Exception:
        return None


def _type_sint(bits: int):
    if not bn:
        return None
    try:
        return bn.Type.int(bits // 8, True)
    except Exception:
        return None


def _type_array(element_type, count: int):
    if not bn:
        return None
    ctor = getattr(bn.Type, "array", None)
    if callable(ctor):
        try:
            return ctor(element_type, count)
        except Exception:
            return None
    return None


def _type_width(type_obj) -> int | None:
    if type_obj is None:
        return None
    for attr in ("width", "size"):
        try:
            value = getattr(type_obj, attr, None)
        except Exception:
            continue
        if isinstance(value, int):
            return value
    return None


def _type_member_count(type_obj) -> int | None:
    if type_obj is None:
        return None
    target = getattr(type_obj, "target", None) or type_obj
    try:
        members = getattr(target, "members", None)
    except Exception:
        return None
    if members is None:
        return None
    try:
        return len(members)
    except Exception:
        try:
            return len(list(members))
        except Exception:
            return None


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


def _define_opaque_struct_type(bv, name: str, size: int | None = None) -> bool:
    existing = _get_type_by_name(bv, name)
    if existing is not None:
        width = _type_width(existing)
        if width is None or width > 0:
            return True
    if not bn:
        return False

    if size is None:
        # Clang treats empty structs as 1 byte; Binja's 0-byte structs cause noisy conversion warnings.
        size = 1

    sb = _structure_builder_create()
    if sb is None:
        return False

    if size is not None:
        width_set = False
        try:
            if hasattr(sb, "width"):
                sb.width = int(size)
                width_set = True
        except Exception:
            pass
        if not width_set:
            # Older APIs may not expose StructureBuilder.width; fall back to a dummy field so
            # the resulting type has a stable non-zero size.
            try:
                u8 = _type_u8()
                arr = _type_array(u8, int(size)) if u8 is not None else None
                append = getattr(sb, "append", None)
                if callable(append) and arr is not None:
                    append(arr, "_opaque")
            except Exception:
                pass

    struct_type = _type_structure(sb)
    if struct_type is None:
        return False
    if existing is not None:
        return _define_or_replace_user_type(bv, name, struct_type)
    return _define_user_type(bv, name, struct_type)


def _parse_types_from_source(bv, source: str, *, filename: str | None = None, include_dirs: list[str] | None = None):
    if not filename:
        raise ValueError("filename is required for type source parsing")

    platform = _require_platform(bv)
    include_dirs = include_dirs or []

    parse_from_source = getattr(platform, "parse_types_from_source", None)
    if callable(parse_from_source):
        return parse_from_source(source, filename=filename, include_dirs=include_dirs, auto_type_source="user")

    type_parser = _require_type_parser()
    parsed, errors = type_parser.parse_types_from_source(
        source,
        filename,
        platform,
        existing_types=bv,
        include_dirs=include_dirs,
        auto_type_source="user",
    )
    if errors:
        raise ValueError(f"failed to parse type source {filename}: {_format_type_parser_errors(errors)}")
    if parsed is None:
        raise RuntimeError(f"type source parser returned no result for {filename}")
    return parsed


def _extract_parsed_types(parsed) -> dict:
    if parsed is None:
        raise RuntimeError("type parser returned no result")
    types = getattr(parsed, "types", None)
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
                ],
            )

    include_dirs = []
    repo_root = _find_repo_root(bv)
    if repo_root is not None:
        include_dirs.append(str(repo_root / "third_party" / "headers"))

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
            existing = _get_type_by_name(bv, name_str)
            if existing is not None:
                if not _should_replace_incomplete_type(existing, type_obj):
                    continue
            if not _define_or_replace_user_type(bv, name, type_obj):
                raise RuntimeError(f"failed to define type {name_str} from {header_path}")
            seeded_total += 1

    if seeded_total:
        _log_info(f"Seeded {seeded_total} typedef(s)/struct(s) from repo headers")

    _SEEDED_REPO_HEADERS = True


def _seed_common_types(bv) -> None:
    global _SEEDED_TYPES
    if _SEEDED_TYPES or not bn:
        return

    _seed_repo_headers(bv)

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
    addr_bytes = getattr(getattr(bv, "arch", None), "address_size", None)
    if isinstance(addr_bytes, int) and addr_bytes in (4, 8):
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


def _rewrite_type_tokens(text: str) -> str:
    import re

    if not text:
        return text
    parts = re.split(r"([A-Za-z_][A-Za-z0-9_]*)", text)
    for idx in range(1, len(parts), 2):
        token = parts[idx]
        replacement = _TYPE_REPLACEMENTS.get(token)
        if replacement:
            parts[idx] = replacement
    return "".join(parts)


def _rewrite_unknown_type_tokens(text: str) -> str:
    import re

    if not text:
        return text
    keywords = _type_keywords()
    parts = re.split(r"([A-Za-z_][A-Za-z0-9_]*)", text)
    for idx in range(1, len(parts), 2):
        token = parts[idx]
        if token in keywords:
            continue
        if token.startswith("_func_"):
            parts[idx] = "void"
            continue
        if token.endswith("_vtbl"):
            parts[idx] = "void *"
            continue
        if token.endswith("_t"):
            parts[idx] = "int"
    return "".join(parts)


def _sanitize_signature(signature: str) -> str:
    # Ghidra-derived signatures sometimes use C++ keywords for parameter names (e.g. `this`).
    # Binja's parser may treat these as reserved depending on the language mode.
    import re

    signature = re.sub(r"\bthis\b", "self", signature)
    return _rewrite_type_tokens(signature)


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


def _parse_hex_size_hint(comment: str) -> int | None:
    import re

    if not comment:
        return None
    patterns = [
        r"\b0x([0-9a-fA-F]+)\s*-?\s*byte\b",
        r"\b0x([0-9a-fA-F]+)\s+bytes?\b",
        r"\bstride\s+0x([0-9a-fA-F]+)\b",
    ]
    for pat in patterns:
        m = re.search(pat, comment)
        if not m:
            continue
        try:
            value = int(m.group(1), 16)
        except Exception:
            continue
        if 0 < value <= 0x100000:
            return value
    return None


def _ensure_types_for_decl(bv, decl: str) -> None:
    import re

    if not bn or not decl:
        return

    keywords = _type_keywords()

    decl = decl.strip().rstrip(";")

    ptr_base = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*\*", decl))
    candidates: set[str] = set()

    prefix, sep, suffix = decl.partition("(")
    if sep:
        # Remove function name from the return-type prefix (last identifier before '(').
        m = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*$", prefix.strip())
        return_part = prefix[: m.start()] if m else prefix
        candidates.update(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", return_part))

        params = suffix.rsplit(")", 1)[0] if ")" in suffix else suffix
        for param in [p.strip() for p in params.split(",") if p.strip()]:
            if param == "void":
                continue
            ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", param)
            if not ids:
                continue
            idx = 0
            while idx < len(ids) and ids[idx] in ("const", "volatile", "signed", "unsigned"):
                idx += 1
            if idx < len(ids) and ids[idx] in ("struct", "union", "enum"):
                idx += 1
            if idx < len(ids):
                candidates.add(ids[idx])
    else:
        candidates.update(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", decl))

    void_ptr = _bn_void_ptr_type(bv)

    for name in sorted(candidates):
        if name in keywords:
            continue
        if _get_type_by_name(bv, name) is not None:
            continue

        # Prefer opaque structs when used as pointer bases (e.g. FILE *).
        if name in ptr_base:
            _define_opaque_struct_type(bv, name)
            continue

        # Heuristic: many library typedefs are pointer-ish (png_structp, z_streamp, etc.).
        if name.endswith("p") and void_ptr is not None:
            _define_alias_type(bv, name, void_ptr)
            continue

        # Fallback: define unknown type names as void* aliases so signature parsing can proceed.
        if void_ptr is not None:
            _define_alias_type(bv, name, void_ptr)


def _resolve_data_type(bv, type_text: str):
    _seed_common_types(bv)
    return _parse_type_string(bv, _rewrite_type_tokens(type_text))


def _apply_function_signature(bv, func, signature: str) -> None:
    _seed_common_types(bv)

    signature = _sanitize_signature(signature)
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

    if hasattr(func, "set_user_type"):
        func.set_user_type(func_type)
        return
    if hasattr(func, "function_type"):
        func.function_type = func_type
        return
    if hasattr(func, "type"):
        func.type = func_type
        return
    raise RuntimeError(f"function {getattr(func, 'name', '<unnamed>')} does not expose a writable type API")


def _set_function_comment(func, comment: str) -> None:
    if hasattr(func, "comment"):
        func.comment = comment
        return
    if hasattr(func, "set_comment"):
        func.set_comment(comment)
        return
    if hasattr(func, "set_comment_at"):
        func.set_comment_at(func.start, comment)
        return
    raise RuntimeError(f"function {getattr(func, 'name', '<unnamed>')} does not expose a writable comment API")


def _set_data_comment(bv, addr: int, comment: str) -> None:
    if hasattr(bv, "set_comment_at"):
        bv.set_comment_at(addr, comment)
        return
    raise RuntimeError(f"BinaryView does not expose set_comment_at for data comment at 0x{addr:x}")


def _ensure_address_valid(bv, addr: int) -> bool:
    if hasattr(bv, "is_valid_address"):
        return bool(bv.is_valid_address(addr))
    if hasattr(bv, "is_valid_offset"):
        return bool(bv.is_valid_offset(addr))
    if hasattr(bv, "get_segment_at"):
        return bv.get_segment_at(addr) is not None
    return True


def _entry_label(row: dict, addr: int | None = None) -> str:
    name = row.get("name") or "<unnamed>"
    if addr is None:
        addr = _parse_address(row.get("address"))
    addr_text = f"0x{addr:x}" if addr is not None else str(row.get("address"))
    return f"{name} @ {addr_text}"


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
        "comments": 0,
        "created": 0,
        "missing": 0,
        "skipped": 0,
    }

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
        func = bv.get_function_at(addr)
        if func is None and row.get("create"):
            containing = []
            if hasattr(bv, "get_functions_containing"):
                containing = list(bv.get_functions_containing(addr))
            if containing:
                raise RuntimeError(f"refusing to create {_entry_label(row, addr)} inside an existing function")
            bv.create_user_function(addr)
            func = bv.get_function_at(addr)
            if func:
                stats["created"] += 1
        if func is None:
            raise LookupError(f"function not found for {_entry_label(row, addr)}")

        changed = False
        name = row.get("name") or ""
        if name and getattr(func, "name", None) != name:
            try:
                func.name = name
                stats["renamed"] += 1
                changed = True
            except Exception as exc:
                raise RuntimeError(f"rename failed for {_entry_label(row, addr)}") from exc

        signature = row.get("signature") or ""
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

        if changed:
            stats["applied"] += 1

    _log_info(f"Applied name map: {map_path}")
    _log_info(
        "Updated entries: {applied} (renamed {renamed}, signatures {signatures}, comments {comments})".format(
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
                except Exception as exc:
                    raise RuntimeError(f"create label failed for {_entry_label(row, addr)}") from exc
            elif getattr(existing, "name", None) != name:
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
            try:
                if hasattr(bv, "define_user_data_var"):
                    bv.define_user_data_var(addr, data_type)
                elif hasattr(bv, "define_data_var"):
                    bv.define_data_var(addr, data_type)
                else:
                    raise RuntimeError("BinaryView does not expose a writable data variable API")
                stats["types"] += 1
                changed = True
            except Exception as exc:
                raise RuntimeError(f"type apply failed for {_entry_label(row, addr)} ({type_text})") from exc

        if changed:
            stats["applied"] += 1

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
