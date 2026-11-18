"""Bind freeware data storage proofs to their original addresses and producing objects."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import pefile

from . import (
    match,
    match_builds,
    match_freeware_definitions,
    match_freeware_sizes,
    match_freeware_storage,
    match_freeware_vtable,
)
from . import match_freeware_data_maps as maps

Row = dict[str, Any]


def _pe_relocations(path: Path) -> dict[int, int] | None:
    with pefile.PE(str(path), fast_load=True) as pe:
        if pe.FILE_HEADER.Characteristics & 1:
            return None
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        return {base + entry.rva: entry.type for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", ())
                for entry in block.entries if entry.type}


def _witnesses(placements: list[Row]) -> dict[tuple[str, int, int, str], tuple[Row, Row]]:
    return {(p["image"], p["address"], ref["function"], ref["symbol"]): (p, ref)
            for p in placements for ref in p["references"]}


def _identity(function: Row, location: Row, ref: Row, extent: str) -> Row:
    pooled = extent in {"vc6-real-literal", "vc6-string-literal"}
    # Identical linker-folded compiler constants can serve multiple .obj files.
    # Attribute private source storage or use separately reviewed native ownership.
    owner = location["owner"]
    if owner == "unknown" and not pooled and (extent == "vc6-sizeof" or "@?" in ref["symbol"]):
        owner = "game"
    return {
        "image": function["image"], "name": ref["name"] if ref["name"] in location["names"] else ref["symbol"],
        "source": function["source"], "owner": owner, "proof_kind": "source-object",
        "symbol": ref["symbol"], "function": function["address"], "reference_site": ref["site"],
        "object_sha256": function["proof"]["candidate_object_sha256"],
    }


def _emitted(
    version: str, placements: list[Row], contexts: list[maps.Context], paths: dict[str, Path],
) -> list[Row]:
    by_producer = defaultdict(list)
    for location in placements:
        for ref in location["references"]:
            by_producer[location["image"], ref["function"]].append((location, ref))
    images = {name: match.load_image(path) for name, path in paths.items()}
    relocations = {name: _pe_relocations(path) for name, path in paths.items()}
    selected = {}
    sizes: dict[match.ScratchConfig, set[str]] = defaultdict(set)
    for function, config, obj, bindings in contexts:
        image = function["image"]
        symbols = defaultdict(list)
        for symbol in obj.symbols:
            symbols[symbol.name].append(symbol)
        for placement, ref in by_producer[image, function["address"]]:
            address = placement["address"]
            possible = symbols[ref["symbol"]]
            # The original may hold two copies of a compiler literal that this TU folds.
            # Each positional operand then proves a separate copy of the same bytes.
            if not ref["symbol"].startswith(("__real@", "??_C@")):
                possible = [symbol for symbol in possible if bindings.get(symbol.raw_index) == address]
            if len(possible) != 1:
                continue
            symbol = possible[0]
            declared = match_freeware_sizes.declared_size(version, function["source"], symbol.name)
            proof = match_freeware_storage.prove(obj, symbol, address, images[image], bindings=bindings,
                                                 relocations=relocations[image], declared_size=declared)
            if proof is None:
                continue
            if proof["extent_evidence"] == "vc6-sizeof":
                sizes[config].add(symbol.name)
            receipt = {**proof, **_identity(function, placement, ref, proof["extent_evidence"])}
            # Several exact functions can emit the same linker-folded string or float.
            identity = (image, address, proof["size"], symbol.name)
            previous = selected.get(identity)
            if previous is None or function["address"] < previous["function"]:
                selected[identity] = receipt
    for config, symbols in sizes.items():
        match_freeware_sizes.verify_declared_sizes(version, config, symbols)
    return list(selected.values())


def _validate_emitted(version: str, functions: list[Row], placements: list[Row], receipts: list[Row],
                      paths: dict[str, Path]) -> None:
    by_function = {(f["image"], f["address"]): f for f in functions if f.get("native_kind") == "function"}
    witnesses = _witnesses(placements)
    images = {name: match.load_image(path) for name, path in paths.items()}
    relocations = {name: _pe_relocations(path) for name, path in paths.items()}
    anchors = {(p["image"], p["address"], ref["symbol"]) for p in placements for ref in p["references"]}
    seen = set()
    for row in receipts:
        image, address, function_va, symbol = row["image"], row["address"], row["function"], row["symbol"]
        identity = (image, address, row["size"], symbol)
        placement = witnesses.get((image, address, function_va, symbol))
        fn = by_function.get((image, function_va))
        if (identity in seen or placement is None or fn is None or fn["ownership"] != "game" or not fn["matched"]
                or fn["candidate"] != "source" or not fn["proof"]["body_byte_exact"]):
            raise ValueError("data object has no unique byte-exact source placement")
        seen.add(identity)
        expected = _identity(fn, *placement, row["extent_evidence"])
        if any(row.get(key) != value for key, value in expected.items()):
            raise ValueError(f"{row['name']}: data source, object or reference differs")
        if row["extent_evidence"] == "vc6-sizeof" and (
            match_freeware_sizes.declared_size(version, fn["source"], symbol) != row["size"]
        ):
            raise ValueError(f"{row['name']}: checked source declaration differs")
        match_freeware_storage.validate(row, images[image], relocations=relocations[image])
        for fixup in row["relocations"]:
            if (image, fixup["target"], fixup["symbol"]) not in anchors:
                target = by_function.get((image, fixup["target"]))
                if target is None or not target["matched"] or target["name"] != match._symbol_lookup_name(fixup["symbol"]):
                    raise ValueError(f"{row['name']}: initializer target has no independent native placement")


def _unsupported_storage(version: str, functions: list[Row], placements: list[Row],
                         emitted: list[Row]) -> dict[tuple[str, int], list[str]]:
    """Preserve an explicit disposition for every literal or reviewed sizeof expression."""
    sources = {(f["image"], f["address"]): f["source"] for f in functions if f.get("candidate") == "source"}
    matched = {(r["image"], r["address"], r["symbol"]) for r in emitted}
    missing = {}
    for place in placements:
        image, address = place["image"], place["address"]
        symbols = {
            r["symbol"] for r in place["references"]
            if (image, address, r["symbol"]) not in matched
            and (r["symbol"].startswith(("__real@", "??_C@"))
                 or match_freeware_sizes.declared_size(version, sources[image, r["function"]], r["symbol"]) is not None)
        }
        if symbols:
            missing[image, address] = sorted(symbols)
    return missing



def _order(row: Row) -> tuple[str, int, str, str, str]:
    return row["image"], row["address"], row["name"], row["proof_kind"], row["source"]


def refresh(version: str, functions: list[Row], statuses: list[match.ScratchStatus]) -> tuple[list[Row], list[Row]]:
    paths = {name: image.path for name, image in match_builds.load_registry().builds[version].items()}
    placements, contexts = maps.refresh(version, functions, statuses)
    receipts = _emitted(version, placements, contexts, paths)
    missing = _unsupported_storage(version, functions, placements, receipts)
    for place in placements:
        if symbols := missing.get((place["image"], place["address"])):
            place["unverified_storage"] = symbols
    receipts.extend(match_freeware_definitions.candidates(version, placements, functions, paths))
    receipts.extend(match_freeware_vtable.candidates(version, placements, functions, paths, contexts=contexts))
    return placements, sorted(receipts, key=_order)


def validate(version: str, functions: list[Row], placements: list[Row], candidates: list[Row]) -> None:
    paths = {name: image.path for name, image in match_builds.load_registry().builds[version].items()}
    maps.validate(version, functions, [{key: value for key, value in row.items() if key != "unverified_storage"}
                                       for row in placements])
    groups = defaultdict(list)
    for row in candidates:
        groups[row["proof_kind"]].append(row)
    if set(groups) - {"source-object", "reviewed-definition", "engine-vtable"} or candidates != sorted(candidates, key=_order):
        raise ValueError("unknown or unordered freeware data proofs")
    emitted = groups["source-object"]
    _validate_emitted(version, functions, placements, emitted, paths)
    missing = _unsupported_storage(version, functions, placements, emitted)
    if any(place.get("unverified_storage") != missing.get((place["image"], place["address"])) for place in placements):
        raise ValueError("missing or incorrect freeware source-storage disposition")
    match_freeware_definitions.candidates(version, placements, functions, paths, saved=groups["reviewed-definition"])
    match_freeware_vtable.candidates(version, placements, functions, paths, saved=groups["engine-vtable"])
