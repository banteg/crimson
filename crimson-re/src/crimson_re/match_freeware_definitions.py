"""Recompile reviewed freeware definitions and locate them through exact native consumers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

import pefile

from . import match as matchlib
from . import match_builds, match_data_report, match_freeware_storage

PROVIDERS = {
    "freeware_game_pools": "crimson.exe",
    "freeware_game_state": "crimson.exe",
    "freeware_game_scalars": "crimson.exe",
    "freeware_game_defaults": "crimson.exe",
    "freeware_grim": "grim.dll",
}
COMPILER = "msvc6.5"
VERSIONS = {"1.0.2", "1.3.0", "1.4.0"}
STORAGE_KINDS = {"coff-bss", "coff-data", "coff-common"}


def _plan(version: str, path: Path) -> list[dict[str, Any]]:
    if version not in VERSIONS:
        raise ValueError(f"unsupported freeware definition version: {version}")
    plan = []
    used = set()
    for spec in json.loads(path.read_text()):
        name = spec["name"]
        if not re.fullmatch(r"[A-Za-z_]\w*", name) or name in used:
            raise ValueError(f"{path.name}: invalid or duplicate data definition {name}")
        used.add(name)
        sizes = dict.fromkeys(VERSIONS, spec["size"]) if "size" in spec else spec["sizes"]
        if not sizes or sizes.keys() - VERSIONS or any(type(size) is not int or size <= 0 for size in sizes.values()):
            raise ValueError(f"{name}: invalid freeware object extent")
        if version not in sizes:
            continue
        size = sizes[version]
        function = spec["extent_function"] if "extent_function" in spec else spec["extent_functions"][version]
        if "initializers" in spec:
            expected = bytes.fromhex(spec["initializers"][version])
        elif "initializer_hex" in spec:
            expected = bytes.fromhex(spec["initializer_hex"])
        else:
            expected = bytes(size)
        if len(expected) != size:
            raise ValueError(f"{name}: initializer length differs from its reviewed extent")
        links = {key: spec[key] for key in ("points_to", "located_through") if key in spec}
        if len(links) > 1 or any(not re.fullmatch(r"[A-Za-z_]\w*", target) for target in links.values()):
            raise ValueError(f"{name}: invalid symbolic data link")
        plan.append({"name": name, "size": size, "extent_function": function, "expected": expected, **links})
    return plan


def _compile(source: Path, build_number: int, plan: list[dict[str, Any]]) -> tuple[matchlib.CoffObject, str]:
    source_name = "Z:" + str(source.resolve()).replace("/", "\\")
    assertions = "\n".join(f"typedef char assert_size_{row['name']}[(sizeof({row['name']}) == {row['size']}) ? 1 : -1];"
                           for row in plan)
    with tempfile.TemporaryDirectory(prefix="crimson-fwdata-") as temporary:
        directory = Path(temporary)
        (directory / "verify.cpp").write_text(f'#include "{source_name}"\n{assertions}\n')
        result = subprocess.run(
            [str(matchlib.DEFAULT_MATCH_ROOT / "cl.sh"), "/c", "/O2", "/Zl", f"/DCL_BUILD={build_number}",
             "/Fodata.obj", "verify.cpp"],
            cwd=directory, env={**os.environ, "MSVC_VER": COMPILER}, capture_output=True, text=True, check=False,
        )
        if result.returncode:
            raise ValueError(f"freeware data compilation failed for {source.name}:\n{result.stdout}{result.stderr}")
        raw = (directory / "data.obj").read_bytes()
    return matchlib.parse_coff_object(raw), matchlib.coff_sha256(raw)


def _external_name(symbol: str) -> str | None:
    """Only C / global-namespace C++ data names can bind an external definition."""
    if symbol.startswith("_") and not symbol.startswith("__imp_"):
        return symbol[1:]
    if (name := re.match(r"^\?(\w+)@@3", symbol)) is not None:
        return name.group(1)
    return None


def _originals(image_paths: dict[str, Path]) -> dict[str, tuple[list[tuple[int, bytes]], dict[int, int]]]:
    originals = {}
    for image, path in image_paths.items():
        with pefile.PE(str(path), fast_load=True) as pe:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
            base = int(pe.OPTIONAL_HEADER.ImageBase)
            sections = []
            for section in pe.sections:
                size = int(section.Misc_VirtualSize)
                if section.Name.rstrip(b"\0").decode("ascii") in match_data_report.DATA_SECTIONS and size:
                    raw = section.get_data()[:size]
                    sections.append((base + int(section.VirtualAddress), raw.ljust(size, b"\0")))
            relocations = {
                base + entry.rva: entry.type for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", ())
                for entry in block.entries if entry.type
            }
            originals[image] = sections, relocations
    return originals


def _verify_original(
    name: str, address: int, expected: bytes, sections: list[tuple[int, bytes]], relocations: dict[int, int],
    *, pointer: bool = False,
) -> None:
    end = address + len(expected)
    for base, data in sections:
        if base <= address and end <= base + len(data):
            if (not match_freeware_storage._pe_relocations_agree(relocations, address, len(expected), [0] if pointer else [])
                    or data[address - base:end - base] != expected):
                raise ValueError(f"{name}: native initializer or pointer relocations differ at {address:#x}")
            return
    raise ValueError(f"{name}: native extent is outside a data section at {address:#x}")


def _unique_signature(sections: list[tuple[int, bytes]], signature: bytes) -> int:
    """Locate the complete reviewed format signature independently of the pointer."""
    locations = []
    for base, data in sections:
        offset = data.find(signature)
        if offset >= 0:
            if data.find(signature, offset + 1) >= 0:
                raise ValueError("ambiguous native format signature")
            locations.append(base + offset)
    if len(locations) != 1:
        raise ValueError("missing or ambiguous native format signature")
    return locations[0]


def candidates(
    version: str, globals_: list[dict[str, Any]], functions: list[dict[str, Any]], image_paths: dict[str, Path],
    *, saved: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Compile during refresh. Recheck the original extent and placement during ordinary verification."""
    originals = _originals(image_paths)
    functions_by_name = {
        (row["image"], row["name"]): row for row in functions
        if row.get("ownership") == "game" and row.get("candidate") == "source" and row.get("matched")
        and row["proof"]["body_byte_exact"]
    }
    references = defaultdict(list)
    for glob in globals_:
        for ref in glob["references"]:
            if name := _external_name(ref["symbol"]):
                references[glob["image"], name].append((glob["address"], ref))
    saved_by_name = {(row["image"], row["name"]): row for row in saved or []}
    seen = set()
    results = []
    registry = match_builds.load_registry()
    for stem, image in PROVIDERS.items():
        source = matchlib.DEFAULT_MATCH_ROOT / "data" / f"{stem}.cpp"
        plan = _plan(version, source.with_suffix(".json"))
        if not plan:
            continue
        obj = None
        object_hash = None
        if saved is None:
            obj, object_hash = _compile(source, registry.image(version, image).cl_build, plan)
        by_name = {row["name"]: row for row in plan}
        for spec in plan:
            name = spec["name"]
            key = image, name
            if key in seen:
                raise ValueError(f"duplicate freeware definition for {key}")
            seen.add(key)
            witness = functions_by_name.get((image, spec["extent_function"]))
            pointer_name = spec.get("located_through", name)
            placements = references[image, pointer_name]
            addresses = {addr for addr, _ in placements}
            sites = [ref["site"] for _, ref in placements if witness and ref["function"] == witness["address"]]
            if len(addresses) != 1 or not sites or witness is None:
                raise ValueError(f"{version}/{image}/{name}: missing unique exact {spec['extent_function']} placement")
            address = addresses.pop()
            expected = spec["expected"]
            fixups = []
            placement = {}
            if "points_to" in spec or "located_through" in spec:
                pointer = by_name[pointer_name]
                literal = by_name[pointer["points_to"]]
                signature = literal["expected"]
                if (literal.get("located_through") != pointer_name or pointer["size"] != 4
                        or pointer["extent_function"] != literal["extent_function"]
                        or len(signature) < 3 or not signature.endswith(b"\0") or b"\0" in signature[:-1]):
                    raise ValueError(f"{name}: invalid format signature or pointer definition")
                target = _unique_signature(originals[image][0], signature)
                pointer_bytes = target.to_bytes(4, "little")
                _verify_original(pointer_name, address, pointer_bytes, *originals[image], pointer=True)
                if name == pointer_name:
                    expected = pointer_bytes
                    fixups = [{"offset": 0, "symbol": "_" + literal["name"], "address": target}]
                    placement = {"relocations": fixups}
                else:
                    placement = {"pointer_witness": address}
                    address = target
            if not fixups:
                _verify_original(name, address, expected, *originals[image])
            if obj is not None:
                storage = match_data_report._check_storage(obj, name, spec["size"], expected=expected, relocations=fixups)
            else:
                previous = saved_by_name.get(key, {})
                storage = previous.get("storage")
                digest = previous.get("object_sha256")
                if (storage not in STORAGE_KINDS or (any(expected) and storage != "coff-data")
                        or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)
                        or (object_hash is not None and object_hash != digest)):
                    raise ValueError(f"{name}: missing or inconsistent freeware compiled data receipt")
                object_hash = digest
            results.append({
                "image": image, "address": address, "size": spec["size"], "name": name, "owner": "game",
                "source": source.relative_to(matchlib.REPO_ROOT).as_posix(), "compiler": COMPILER, "storage": storage,
                "object_sha256": object_hash, "initializer_sha256": hashlib.sha256(expected).hexdigest(),
                "proof_kind": "reviewed-definition", "extent_function": witness["address"], "reference_site": min(sites),
                **placement,
            })
    results.sort(key=lambda item: (item["image"], item["address"], item["name"]))
    if saved is not None and results != sorted(saved, key=lambda item: (item["image"], item["address"], item["name"])):
        raise ValueError("freeware definition objects differ from their source placements or original bytes")
    return results
