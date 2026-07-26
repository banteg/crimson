import json
import os
import re

import ida_bytes
import ida_funcs
import ida_typeinf
import idaapi
import idc

PT_FLAGS = ida_typeinf.PT_SIL

HEADER_PATHS = (
    os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "third_party", "headers", "crimsonland_ida_types.h"),
    ),
    os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "third_party", "headers", "crimsonland_types.h"),
    ),
)

HEADER_PRELUDE = """
typedef void *LPDIRECTSOUNDBUFFER;
typedef void *LPDIRECT3D8;
typedef void *LPDIRECT3DDEVICE8;
typedef void *LPDIRECT3DSURFACE8;
typedef __int64 ogg_int64_t;
typedef struct OggVorbis_File OggVorbis_File;
typedef struct vorbis_info vorbis_info;
typedef struct {
    unsigned int (*read_func)(void *ptr, unsigned int size, unsigned int nmemb, void *datasource);
    int (*seek_func)(void *datasource, ogg_int64_t offset, int whence);
    int (*close_func)(void *datasource);
    long (*tell_func)(void *datasource);
} ov_callbacks;
""".strip()

ARRAY_DECL_RE = re.compile(r"^(?P<base>.+?)(?P<arrays>(?:\s*\[[^\]]+\])+)\s*$")
TYPE_SPACE_RE = re.compile(r"\s+")
CALL_CONV_RE = re.compile(r"\b__(?:cdecl|fastcall|stdcall|thiscall|usercall|vectorcall)\b")


def get_argv():
    return list(idc.ARGV)


def basename(path):
    return os.path.basename(path).lower()


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_decl(decl):
    text = (decl or "").replace("\r", "").strip()
    if not text:
        return ""
    if not text.endswith(";"):
        text += ";"
    return text


def normalize_type_text(text):
    text = TYPE_SPACE_RE.sub(" ", (text or "").strip())
    text = re.sub(r"\s*\*\s*", "*", text)
    text = re.sub(r"\s*\[\s*", "[", text)
    text = re.sub(r"\s*\]\s*", "]", text)
    text = re.sub(r"\s*\(\s*", "(", text)
    text = re.sub(r"\s*\)", ")", text)
    text = re.sub(r"\s*,\s*", ", ", text)
    return text


def build_data_decl(type_text, ident="__ida_data"):
    text = (type_text or "").strip()
    if not text:
        raise ValueError("empty type")
    match = ARRAY_DECL_RE.match(text)
    if match:
        return f"{match.group('base').rstrip()} {ident}{match.group('arrays')};"
    return f"{text} {ident};"


def parse_decl_or_raise(decl, context):
    normalized = normalize_decl(decl)
    if not normalized:
        raise RuntimeError(f"empty declaration for {context}")
    tinfo = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(tinfo, None, normalized, PT_FLAGS):
        raise RuntimeError(f"parse_decl failed for {context}: {normalized}")
    return tinfo


def parse_function_decl_or_raise(decl, context):
    normalized = normalize_decl(decl)
    candidates = [normalized]
    without_call_conv = CALL_CONV_RE.sub("", normalized)
    without_call_conv = TYPE_SPACE_RE.sub(" ", without_call_conv).strip()
    if without_call_conv != normalized:
        candidates.append(without_call_conv)
    for candidate in candidates:
        tinfo = ida_typeinf.tinfo_t()
        if ida_typeinf.parse_decl(tinfo, None, candidate, PT_FLAGS):
            return tinfo
    raise RuntimeError(f"parse_decl failed for {context}: {normalized}")


def apply_tinfo_or_raise(ea, tinfo, context):
    ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
    readback = idc.get_type(ea) or ""
    if not readback:
        raise RuntimeError(f"type readback failed for {context} @ 0x{ea:08X}")
    return readback


def load_shared_header():
    chunks = [HEADER_PRELUDE]
    for path in HEADER_PATHS:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read().strip()
        if text:
            chunks.append(text)
    return "\n\n".join(chunks) + "\n"


def install_repo_types():
    errors = ida_typeinf.parse_decls(ida_typeinf.get_idati(), load_shared_header(), None, PT_FLAGS)
    if errors != 0:
        raise RuntimeError(f"parse_decls failed with {errors} error(s)")


def entry_label(row, ea):
    name = row.get("name") or row.get("signature") or row.get("type") or "<unnamed>"
    return f"{name} @ 0x{ea:08X}"


def parse_address(row):
    address = row.get("address", "")
    if not address:
        raise RuntimeError(f"missing address in row: {row}")
    return int(address, 16)


def set_name_or_raise(ea, name, context):
    if not name:
        return False
    current = idc.get_name(ea)
    if current == name:
        return False
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_tail(flags):
        item_head = ida_bytes.get_item_head(ea)
        print(
            f"name skipped for {context}: address is inside the data item at 0x{item_head:08X}",
        )
        return False
    if not idc.set_name(ea, name, idc.SN_NOWARN):
        raise RuntimeError(f"set_name failed for {context}")
    if idc.get_name(ea) != name:
        raise RuntimeError(f"name readback mismatch for {context}")
    return True


def set_func_comment(ea, comment):
    if comment:
        idc.set_func_cmt(ea, comment, 0)


def set_comment(ea, comment):
    if comment:
        idc.set_cmt(ea, comment, 0)


def apply_signature(ea, signature, context):
    if not signature:
        return False
    tinfo = parse_function_decl_or_raise(signature, context)
    apply_tinfo_or_raise(ea, tinfo, context)
    return True


def apply_data_type(ea, type_text, context):
    if not type_text:
        return False, 0
    tinfo = parse_decl_or_raise(build_data_decl(type_text), context)
    size = tinfo.get_size()
    if size <= 0:
        raise RuntimeError(f"invalid data type size for {context}")
    if not (tinfo.is_array() or tinfo.is_udt()):
        if not idc.del_items(ea, idc.DELIT_SIMPLE, size):
            raise RuntimeError(f"del_items failed for {context}")
        if tinfo.is_float():
            created = bool(idc.create_data(ea, idc.FF_FLOAT, size, idc.BADADDR))
        elif tinfo.is_double():
            created = bool(idc.create_data(ea, idc.FF_DOUBLE, size, idc.BADADDR))
        elif size == 1:
            created = bool(idc.create_byte(ea))
        elif size == 2:
            created = bool(idc.create_word(ea))
        elif size == 4:
            created = bool(idc.create_dword(ea))
        elif size == 8:
            created = bool(idc.create_qword(ea))
        else:
            raise RuntimeError(f"unsupported scalar size for {context}: {size}")
        if not created:
            raise RuntimeError(f"scalar item creation failed for {context}")
    readback = apply_tinfo_or_raise(ea, tinfo, context)
    if normalize_type_text(readback) != normalize_type_text(type_text):
        raise RuntimeError(f"type readback mismatch for {context}: expected {type_text!r}, got {readback!r}")
    if size > 1 and (tinfo.is_array() or tinfo.is_udt()):
        return True, size
    return True, 0


def ensure_function(ea, context):
    explicit_end = idc.BADADDR
    while True:
        func = ida_funcs.get_func(ea)
        if func and func.start_ea == ea:
            return False
        chunk = ida_funcs.get_fchunk(ea)
        if chunk and func and chunk.start_ea != func.start_ea:
            owner_start = func.start_ea
            tail_start = chunk.start_ea
            tail_end = chunk.end_ea
            if not idc.remove_fchunk(owner_start, tail_start):
                raise RuntimeError(f"remove_fchunk failed for {context}")
            if ida_funcs.get_fchunk(ea):
                raise RuntimeError(f"tail chunk still present after remove_fchunk for {context}")
            if tail_start < ea:
                owner = ida_funcs.get_func(owner_start)
                if owner is None or not ida_funcs.append_func_tail(owner, tail_start, ea):
                    raise RuntimeError(f"tail-prefix restore failed for {context}")
            explicit_end = tail_end
            break
        if func and func.start_ea < ea:
            owner_start = func.start_ea
            if not idc.set_func_end(owner_start, ea):
                # IDA refuses to resize a few compiler-generated EH layouts.
                # Rebuild the entry chunk explicitly so the curated boundary
                # remains authoritative across tools.
                if not idc.del_func(owner_start):
                    raise RuntimeError(f"del_func fallback failed for {context}")
                if not ida_funcs.add_func(owner_start, ea):
                    raise RuntimeError(f"add_func fallback failed for owner of {context}")
            next_func = ida_funcs.get_func(ea)
            if next_func and next_func.start_ea < ea:
                raise RuntimeError(f"function still spans target after set_func_end for {context}")
            # Claim the new boundary before auto-analysis has a chance to merge
            # the containing function back across it.
            break
        if func:
            raise RuntimeError(f"unexpected function layout for {context}: owner starts at 0x{func.start_ea:08X}")
        break
    created = (
        ida_funcs.add_func(ea)
        if explicit_end == idc.BADADDR
        else ida_funcs.add_func(ea, explicit_end)
    )
    if not created:
        raise RuntimeError(f"add_func failed for {context}")
    func = idaapi.get_func(ea)
    if not func or func.start_ea != ea:
        raise RuntimeError(f"function creation verification failed for {context}")
    return True


def apply_name_map(path, program_name):
    all_rows = load_json(path)
    rows = [
        row
        for row in all_rows
        if basename(row.get("program", "")) == program_name
    ]
    stats = {
        "updated": 0,
        "renamed": 0,
        "signatures": 0,
        "signature_errors": 0,
        "comments": 0,
        "created": 0,
        "skipped": 0,
    }
    creation_rows = sorted(rows, key=parse_address, reverse=True)
    for row in creation_rows:
        ea = parse_address(row)
        context = entry_label(row, ea)
        if ensure_function(ea, context):
            stats["created"] += 1
    stats["skipped"] = len(all_rows) - len(rows)
    for row in rows:
        ea = parse_address(row)
        context = entry_label(row, ea)
        if set_name_or_raise(ea, row.get("name") or "", context):
            stats["renamed"] += 1
        comment = row.get("comment") or ""
        if comment:
            set_func_comment(ea, comment)
            stats["comments"] += 1
        try:
            if apply_signature(ea, row.get("signature") or "", context):
                stats["signatures"] += 1
        except RuntimeError as error:
            print(f"signature skipped for {context}: {error}")
            stats["signature_errors"] += 1
        stats["updated"] += 1
    return stats


def apply_data_map(path, program_name):
    payload = load_json(path)
    rows = sorted(payload["entries"] if isinstance(payload, dict) else payload, key=parse_address)
    stats = {"updated": 0, "renamed": 0, "types": 0, "type_errors": 0, "comments": 0, "skipped": 0}
    covered_ranges = []

    def is_covered(ea):
        for start, end in covered_ranges:
            if start < ea < end:
                return True
        return False

    for row in rows:
        if basename(row.get("program", "")) != program_name:
            stats["skipped"] += 1
            continue
        ea = parse_address(row)
        if is_covered(ea):
            stats["skipped"] += 1
            continue
        context = entry_label(row, ea)
        try:
            typed, coverage_size = apply_data_type(ea, row.get("type") or "", context)
        except RuntimeError as error:
            print(f"data type skipped for {context}: {error}")
            typed, coverage_size = False, 0
            stats["type_errors"] += 1
        if typed:
            stats["types"] += 1
        if coverage_size:
            covered_ranges.append((ea, ea + coverage_size))
        if set_name_or_raise(ea, row.get("name") or "", context):
            stats["renamed"] += 1
        comment = row.get("comment") or ""
        if comment:
            set_comment(ea, comment)
            stats["comments"] += 1
        stats["updated"] += 1
    return stats
