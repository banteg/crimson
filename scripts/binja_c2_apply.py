"""
Apply the tracked C2.DLL annotations to a Binary Ninja view.

The pinned VC6 back end (``tools/match/compilers/msvc6.5/Bin/C2.DLL``) is
annotated from two files under ``analysis/binary_ninja/c2``:

- ``c2_types.h``: compiler data structures, parsed and defined as user types.
- ``c2_symbols.json``: function names, prototypes and comments, data names and
  types, and instruction comments, keyed by virtual address.

Usage:
  bn py exec --target C2.DLL.bndb --script scripts/binja_c2_apply.py

The script is idempotent. It refuses a view whose raw bytes do not hash to the
pinned C2.DLL.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import binaryninja as bn

C2_SHA256 = "d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a"


def _repo_root(bv) -> Path:
    bases = [Path(bv.file.filename).resolve().parent]
    if "__file__" in globals():
        bases.append(Path(__file__).resolve().parent)
    bases.append(Path.cwd())
    for base in bases:
        for candidate in (base, *base.parents):
            if (candidate / "analysis" / "binary_ninja" / "c2").is_dir():
                return candidate
    raise RuntimeError("cannot locate the crimson checkout from the view or script path")


def _check_binary(bv) -> None:
    raw = bv.file.raw
    digest = hashlib.sha256(raw.read(raw.start, raw.length)).hexdigest()
    if digest != C2_SHA256:
        raise RuntimeError(f"view is not the pinned C2.DLL (sha256 {digest})")


def _apply_types(bv, header: Path) -> int:
    # The platform parser ignores types already in the view, so re-running replaces them.
    parsed = bv.platform.parse_types_from_source(header.read_text(), filename=header.name)
    for name, type_obj in parsed.types.items():
        bv.define_user_type(name, type_obj)
    return len(parsed.types)


def _apply_functions(bv, rows: dict) -> int:
    for key, row in rows.items():
        address = int(key, 16)
        function = bv.get_function_at(address)
        if function is None:
            bv.create_user_function(address)
            bv.update_analysis_and_wait()
            function = bv.get_function_at(address)
        function.name = row["name"]
        if "prototype" in row:
            function.type = bv.parse_type_string(row["prototype"])[0]
        if "comment" in row:
            function.comment = row["comment"]
    return len(rows)


def _apply_data(bv, rows: dict) -> int:
    for key, row in rows.items():
        address = int(key, 16)
        if "type" in row:
            bv.define_user_data_var(address, bv.parse_type_string(row["type"])[0])
        bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, address, row["name"]))
        if "comment" in row:
            bv.set_comment_at(address, row["comment"])
    return len(rows)


def _apply_comments(bv, rows: dict) -> int:
    for key, text in rows.items():
        address = int(key, 16)
        functions = bv.get_functions_containing(address)
        if functions:
            for function in functions:
                function.set_comment_at(address, text)
        else:
            bv.set_comment_at(address, text)
    return len(rows)


def apply(bv) -> None:
    _check_binary(bv)
    root = _repo_root(bv) / "analysis" / "binary_ninja" / "c2"
    symbols = json.loads((root / "c2_symbols.json").read_text())
    counts = {"types": _apply_types(bv, root / "c2_types.h")}
    counts["data"] = _apply_data(bv, symbols["data"])
    counts["functions"] = _apply_functions(bv, symbols["functions"])
    counts["comments"] = _apply_comments(bv, symbols["comments"])
    bv.update_analysis_and_wait()
    print(" ".join(f"{name}={count}" for name, count in counts.items()))


apply(bv)  # noqa: F821  # provided by Binary Ninja's script scope
