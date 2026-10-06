"""Link small, closed source components at their reference virtual addresses.

Unbuilt regions are zero-filled layout reservations, excluded from all credit.
This produces a passive PE component, not a runnable replacement for the game.
Only supported COFF layouts with concrete source-backed relocation targets pass.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
from pathlib import Path
from typing import Any

import pefile

from . import match as matchlib
from . import match_data_report, match_toolchain, native_link

PLAN = matchlib.REPO_ROOT / "tools/native/reference_layout.json"
OUTPUT = matchlib.REPO_ROOT / "artifacts/native-reference-link"
POLICY = "source-component-native-placement-v1"
PERMISSIONS = 0xE0000000


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _relative(path: Path) -> str:
    relative = matchlib.repo_relative_path(path)
    if relative is None:
        raise ValueError(f"{path} is outside repository root {matchlib.REPO_ROOT}")
    return relative


def _plan(functions: list[dict[str, Any]], data: dict[str, Any]) -> list[dict[str, Any]]:
    plan = json.loads(PLAN.read_text())
    if plan.get("schema") != 1 or plan.get("version") != "1.9.93":
        raise ValueError("unsupported reference-layout plan")
    result: list[dict[str, Any]] = []
    for spec in plan["components"]:
        image = spec["image"]
        clusters = json.loads((matchlib.REPO_ROOT / f"tools/native/translation_units/{image}.json").read_text())
        cluster = next(c for c in clusters["clusters"] if c["name"] == spec["cluster"])
        config = matchlib.load_scratch_config(matchlib.DEFAULT_MATCH_ROOT / "scratches" / cluster["scratch"])
        source = _relative(config.directory / config.source)
        rows = []
        for member in cluster["members"]:
            row = next(r for r in functions if r["image"] == image and r["name"] == member["function"])
            if row["candidate"] != "source" or not row["matched"] or row["source"] != source:
                raise ValueError(f"reference-layout member lacks matched source: {member['function']}")
            rows.append({"image": image, "name": row["name"], "symbol": member["symbol"],
                         "address": row["address"], "size": row["size"], "source": source,
                         "object_sha256": row["proof"]["candidate_object_sha256"]})
        storage = [r for r in data["candidates"] if r["image"] == image and r["source"] == spec["data_source"]]
        if not storage or any(r["relocations"] or r["storage"] != "coff-data" for r in storage):
            raise ValueError("reference-layout data must have concrete, literal source storage")
        result.append({"spec": spec, "config": config, "code": sorted(rows, key=lambda r: r["address"]),
                       "data": sorted(storage, key=lambda r: r["address"])})
    keys = [(r["image"], r["address"]) for c in result for r in c["code"] + c["data"]]
    if len(set(keys)) != len(keys):
        raise ValueError("overlapping reference-layout components")
    return result


def _reservation_object(sections: list[tuple[str, int, int]]) -> bytes:
    """Emit zero-filled COFF reservations without symbols or reference payloads."""
    if any(size < 0 or len(name) > 8 for name, size, _ in sections):
        raise ValueError("invalid layout reservation")
    header = 20 + 40 * len(sections)
    out = bytearray(header)
    struct.pack_into("<HHIIIHH", out, 0, 0x14C, len(sections), 0, header + sum(s[1] for s in sections), 0, 0, 0)
    for index, (name, size, flags) in enumerate(sections):
        offset = 20 + index * 40
        out[offset:offset + 8] = name.encode().ljust(8, b"\0")
        struct.pack_into("<IIIIIIHHI", out, offset + 8, 0, 0, size, len(out), 0, 0, 0, 0, flags | 0x100000)
        out.extend(bytes(size))
    out.extend(struct.pack("<I", 4))
    return bytes(out)


def _adapt_code(raw: bytes, rows: list[dict[str, Any]]) -> tuple[bytes, list[dict[str, Any]], int]:
    """Rename code subsection metadata; preserve compiler bytes and relocation records."""
    obj = matchlib.parse_coff_object(raw)
    symbols = {s.name: s for s in obj.symbols}
    by_index = {s.raw_index: s for s in obj.symbols}
    code_sections = [s for s in obj.sections if s.characteristics & 0x20000000 and s.data]
    selected = [symbols[row["symbol"]] for row in rows]
    if [s.section_number for s in selected] != [s.index for s in code_sections]:
        raise ValueError("reference-layout object must contain exactly the ordered cluster code sections")
    out = bytearray(raw)
    out[4:8] = bytes(4)
    symbol_table = struct.unpack_from("<I", raw, 8)[0]
    for symbol in obj.symbols:
        if symbol.storage_class == 3 and symbol.name == ".text" and symbol.section_number in {s.index for s in code_sections}:
            offset = symbol_table + 18 * symbol.raw_index
            out[offset:offset + 8] = b".text$M\0"
    cursor = rows[0]["address"]
    relocations = []
    for row, symbol, section in zip(rows, selected, code_sections, strict=True):
        if (symbol.value != 0 or section.name != ".text" or row["address"] != cursor
                or row["size"] > len(section.data)):
            raise ValueError("compiler section layout differs from native cluster organization")
        offset = 20 + 40 * (section.index - 1)
        out[offset:offset + 8] = b".text$M\0"
        for relocation in section.relocations:
            if (relocation.relocation_type != matchlib.IMAGE_REL_I386_DIR32
                    or not 0 <= relocation.virtual_address <= row["size"] - 4):
                raise ValueError("unsupported component code relocation")
            if struct.unpack_from("<I", section.data, relocation.virtual_address)[0] != 0:
                raise ValueError("reference-layout code relocation has an address addend")
            relocations.append({"address": row["address"] + relocation.virtual_address,
                                "symbol": by_index[relocation.symbol_index].name, "type": 3})
        cursor += len(section.data)
    if any(s.data and s.characteristics & 0xC0000000 and not s.characteristics & 0x22000000 for s in obj.sections):
        raise ValueError("component code object contains additional allocatable storage")
    matchlib.parse_coff_object(bytes(out))
    return bytes(out), relocations, cursor - rows[0]["address"]


def _compile_data(component: dict[str, Any], directory: Path) -> Path:
    # Use the identical sizeof harness and compiler switches as matched-data evidence.
    source = matchlib.REPO_ROOT / component["spec"]["data_source"]
    _, sources = match_data_report._load_plan()
    rows = next(s["rows"] for s in sources if s["source"] == component["spec"]["data_source"])
    include = native_link._wibo_windows_path(source)
    assertions = "\n".join(f"typedef char data_size_{i}[(sizeof({r['name']}) == {r['size']}) ? 1 : -1];"
                           for i, r in enumerate(rows))
    (directory / "verify.cpp").write_text(f'#include "{include}"\n{assertions}\n')
    subprocess.run([str(matchlib.DEFAULT_MATCH_ROOT / "cl.sh"), "/c", "/O2", "/Zl", "/Fodata.obj", "verify.cpp"],
                   cwd=directory, env={**os.environ, "MSVC_VER": component["config"].compiler},
                   capture_output=True, text=True, check=True)
    path = directory / "data.obj"
    raw = path.read_bytes()
    obj = matchlib.parse_coff_object(raw)
    sections = [s for s in obj.sections if s.data and s.characteristics & 0xC0000000]
    if len(sections) != 1 or sections[0].name != ".data$M" or sections[0].relocations:
        raise ValueError("component data must occupy exactly one concrete subsection")
    section = sections[0]
    symbols = {s.name: s for s in obj.symbols if s.section_number == section.index and s.storage_class == 2}
    cursor = component["data"][0]["address"]
    for row in component["data"]:
        symbol = next(s for s in symbols.values() if s.name.startswith(f"?{row['name']}@@3"))
        if row["address"] != cursor or symbol.value != cursor - component["data"][0]["address"]:
            raise ValueError("compiled data layout differs from native storage organization")
        if matchlib.coff_sha256(raw) != row["object_sha256"]:
            raise ValueError("linked data object differs from matched-data compilation")
        cursor += row["size"]
    if len(section.data) != cursor - component["data"][0]["address"]:
        raise ValueError("unclaimed data storage in component")
    return path


def _section(pe: pefile.PE, address: int, size: int) -> Any:
    rva = address - int(pe.OPTIONAL_HEADER.ImageBase)
    all_sections: list[Any] = pe.sections
    sections = [s for s in all_sections if int(s.VirtualAddress) <= rva and rva + size <= int(s.VirtualAddress) + int(s.Misc_VirtualSize)]
    if len(sections) != 1 or size <= 0:
        raise ValueError("linked range is outside a single virtual section")
    return sections[0]


def _relocations(pe: pefile.PE) -> dict[int, int]:
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    result = {}
    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for entry in block.entries:
            if not entry.type:
                continue
            address = base + entry.rva
            if address in result:
                raise ValueError("duplicate PE base-relocation slot")
            result[address] = entry.type
    return result


def _verify_pe(path: Path, component: dict[str, Any], relocations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reference = matchlib._paths_for_image(component["spec"]["image"])[0]
    with pefile.PE(str(reference)) as ref, pefile.PE(str(path)) as linked:
        if (linked.OPTIONAL_HEADER.ImageBase != ref.OPTIONAL_HEADER.ImageBase
                or linked.OPTIONAL_HEADER.AddressOfEntryPoint != 0
                or getattr(linked, "DIRECTORY_ENTRY_IMPORT", [])):
            raise ValueError("component image has unexpected base, entry point or runtime imports")
        actual, expected = linked.get_memory_mapped_image(), ref.get_memory_mapped_image()
        base = int(ref.OPTIONAL_HEADER.ImageBase)
        records = []
        for kind in ("code", "data"):
            for row in component[kind]:
                address, size = row["address"], row["size"]
                left, right = _section(ref, address, size), _section(linked, address, size)
                if (left.Characteristics & PERMISSIONS) != (right.Characteristics & PERMISSIONS):
                    raise ValueError("linked section permissions differ")
                body = expected[address - base:address - base + size]
                if actual[address - base:address - base + size] != body:
                    raise ValueError(f"final linked bytes differ: {row['name']}")
                records.append({"kind": kind, "image": row["image"], "name": row["name"],
                                "address": address, "size": size, "source": row["source"],
                                "object_sha256": row["object_sha256"], "sha256": _sha(body),
                                "permissions": int(left.Characteristics) & PERMISSIONS})
        if _relocations(linked) != {r["address"]: r["type"] for r in relocations}:
            raise ValueError("component PE base relocations differ from source relocations")
        reference_relocs = _relocations(ref)
        for row in component["code"] + component["data"]:
            start, end = row["address"], row["address"] + row["size"]
            if {a: t for a, t in reference_relocs.items() if start - 3 <= a < end} != {
                r["address"]: r["type"] for r in relocations if start <= r["address"] < end
            }:
                raise ValueError("source relocations differ from native relocation slots")
        return records


def refresh(functions: list[dict[str, Any]], data: dict[str, Any]) -> dict[str, Any]:
    components = []
    for component in _plan(functions, data):
        spec, config = component["spec"], component["config"]
        directory = OUTPUT / spec["image"] / spec["cluster"]
        directory.mkdir(parents=True, exist_ok=True)
        code = matchlib.compile_scratch(config, matchlib.DEFAULT_MATCH_ROOT)
        raw = code.read_bytes()
        canonical_hash = matchlib.coff_sha256(raw)
        for row in component["code"]:
            member_config = matchlib.load_scratch_config(matchlib.DEFAULT_MATCH_ROOT / "scratches" / row["name"])
            member_raw = matchlib.compile_scratch(member_config, matchlib.DEFAULT_MATCH_ROOT).read_bytes()
            if not matchlib.coff_sha256(member_raw) == row["object_sha256"] == canonical_hash:
                raise ValueError("linked code object differs from matched-source compilation")
        adapted, relocations, code_size = _adapt_code(raw, component["code"])
        (directory / "code.obj").write_bytes(adapted)
        storage = _compile_data(component, directory)
        obj = matchlib.parse_coff_object(storage.read_bytes())
        symbols = {s.name: s for s in obj.symbols}
        for relocation in relocations:
            symbol = symbols.get(relocation["symbol"])
            if symbol is None or symbol.section_number <= 0:
                raise ValueError("component has a relocation without concrete source storage")
            row = next(r for r in component["data"] if symbol.name.startswith(f"?{r['name']}@@3"))
            relocation["target"] = row["address"]
            relocation["target_name"] = row["name"]
        reference = matchlib._paths_for_image(spec["image"])[0]
        with pefile.PE(str(reference)) as ref:
            base = int(ref.OPTIONAL_HEADER.ImageBase)
            text = _section(ref, component["code"][0]["address"], code_size)
            data_section = _section(ref, component["data"][0]["address"], sum(r["size"] for r in component["data"]))
            middle = [s for s in ref.sections if text.VirtualAddress < s.VirtualAddress < data_section.VirtualAddress]
            if text.Name.rstrip(b"\0") != b".text" or data_section.Name.rstrip(b"\0") != b".data" or any(
                s.Name.rstrip(b"\0") != b".rdata" for s in middle
            ):
                raise ValueError("unsupported reference section layout")
            offset = component["code"][0]["address"] - base - text.VirtualAddress
            reservations = [(".text$A", offset, 0x60000020),
                            (".text$Z", int(text.Misc_VirtualSize) - offset - code_size, 0x60000020),
                            *[(".rdata$A", int(s.Misc_VirtualSize), 0x40000040) for s in middle],
                            (".data$A", component["data"][0]["address"] - base - data_section.VirtualAddress, 0xC0000040)]
            alignment = int(ref.OPTIONAL_HEADER.FileAlignment)
        (directory / "reserved.obj").write_bytes(_reservation_object(reservations))
        providers = native_link.load_native_provider_config(
            matchlib.REPO_ROOT / f"tools/native/providers/{spec['image']}.json", image=spec["image"],
        )
        archive = next(a for a in providers.archives if a.id == spec["archive"])
        archive_receipt = native_link._native_provider_archive_payload(archive, repo_root=matchlib.REPO_ROOT)
        image_path, map_path = directory / "component.dll", directory / "component.map"
        linker = matchlib._compiler_executable_path(config, matchlib.DEFAULT_MATCH_ROOT).parent / "LINK.EXE"
        subprocess.run([str(match_toolchain.resolve_wibo_path(matchlib.DEFAULT_MATCH_ROOT)), str(linker),
                        "/nologo", "/dll", "/noentry", "/nodefaultlib", "/opt:noref", "/machine:ix86",
                        f"/base:0x{base:x}", f"/filealign:{alignment}",
                        f"/out:{native_link._wibo_windows_path(image_path)}", f"/map:{native_link._wibo_windows_path(map_path)}",
                        *[native_link._wibo_windows_path(p) for p in (directory / "reserved.obj", directory / "code.obj", storage, archive.path)]],
                       cwd=directory, capture_output=True, text=True, check=True)
        image_path.write_bytes(native_link.normalize_pe_timestamp(image_path.read_bytes()))
        records = _verify_pe(image_path, component, relocations)
        map_text = map_path.read_text()
        for row in component["code"]:
            if re.search(rf"\s{re.escape(row['symbol'])}\s+{row['address']:08x}\s", map_text) is None:
                raise ValueError("linker map differs from native function placement")
        for row in component["data"]:
            if re.search(rf"\s\?{row['name']}@@3\S+\s+{row['address']:08x}\s", map_text) is None:
                raise ValueError("linker map differs from native data placement")
        components.append({"image": spec["image"], "cluster": spec["cluster"], "records": records,
                           "relocations": relocations, "artifact": _relative(image_path),
                           "artifact_sha256": _sha(image_path.read_bytes()), "archive": archive_receipt,
                           "adapted_object_sha256": matchlib.coff_sha256(adapted), "reservation_sha256": _sha((directory / "reserved.obj").read_bytes()),
                           "linker_sha256": _sha(linker.read_bytes()), "code_object_sha256": canonical_hash})
    receipt = {"schema": 1, "policy": POLICY, "components": components}
    validate(receipt, functions, data)
    (OUTPUT / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def validate(receipt: dict[str, Any], functions: list[dict[str, Any]], data: dict[str, Any]) -> None:
    if receipt.get("schema") != 1 or receipt.get("policy") != POLICY:
        raise ValueError("unsupported reference-layout receipt")
    planned = _plan(functions, data)
    if len(receipt["components"]) != len(planned):
        raise ValueError("reference-layout component inventory differs")
    for saved, component in zip(receipt["components"], planned, strict=True):
        spec = component["spec"]
        if saved["image"] != spec["image"] or saved["cluster"] != spec["cluster"]:
            raise ValueError("reference-layout component identity differs")
        providers = native_link.load_native_provider_config(
            matchlib.REPO_ROOT / f"tools/native/providers/{spec['image']}.json", image=spec["image"],
        )
        archive = next(a for a in providers.archives if a.id == spec["archive"])
        archive_file = saved["archive"]["file"]
        if (saved["archive"]["id"] != archive.id or archive_file["path"] != _relative(archive.path)
                or archive_file["sha256"] != archive.sha256):
            raise ValueError("reference-layout archive identity differs")
        expected_archive = {"id": archive.id, "file": {"path": _relative(archive.path), "repository_relative": True, "sha256": archive.sha256},
                            "provenance": {"manifest": native_link._file_payload(archive.provenance.path, repo_root=matchlib.REPO_ROOT),
                                           "member": archive.provenance.member, "source_artifact": archive.provenance.source_artifact}}
        if saved["archive"] != expected_archive:
            raise ValueError("reference-layout archive provenance differs")
        if archive.path.is_file() and saved["archive"] != native_link._native_provider_archive_payload(archive, repo_root=matchlib.REPO_ROOT):
            raise ValueError("reference-layout archive provenance differs")
        linker = matchlib._compiler_executable_path(component["config"], matchlib.DEFAULT_MATCH_ROOT).parent / "LINK.EXE"
        if linker.is_file() and _sha(linker.read_bytes()) != saved["linker_sha256"]:
            raise ValueError("reference-layout linker changed")
        for row in component["code"]:
            config = matchlib.load_scratch_config(matchlib.DEFAULT_MATCH_ROOT / "scratches" / row["name"])
            obj_path = matchlib._scratch_object_path(config)
            if obj_path.is_file():
                raw = obj_path.read_bytes()
                if matchlib.coff_sha256(raw) != row["object_sha256"] or row["object_sha256"] != saved["code_object_sha256"]:
                    raise ValueError("reference-layout source object changed")
                adapted, relocations, _ = _adapt_code(raw, component["code"])
                if matchlib.coff_sha256(adapted) != saved["adapted_object_sha256"] or [(r["address"], r["symbol"], r["type"]) for r in relocations] != [
                    (r["address"], r["symbol"], r["type"]) for r in saved["relocations"]
                ]:
                    raise ValueError("reference-layout source organization or relocations changed")
        expected = component["code"] + component["data"]
        if len(saved["records"]) != len(expected):
            raise ValueError("reference-layout range inventory differs")
        reference = matchlib._paths_for_image(spec["image"])[0]
        with pefile.PE(str(reference)) as ref:
            mapped = ref.get_memory_mapped_image()
            base = int(ref.OPTIONAL_HEADER.ImageBase)
            native_relocs = _relocations(ref)
            expected_relocs = []
            for record, row in zip(saved["records"], expected, strict=True):
                kind = "code" if row in component["code"] else "data"
                start, size = row["address"], row["size"]
                body = mapped[start - base:start - base + size]
                expected_record = {key: row[key] for key in ("image", "name", "address", "size", "source", "object_sha256")}
                expected_record.update(kind=kind, sha256=_sha(body), permissions=int(_section(ref, start, size).Characteristics) & PERMISSIONS)
                if record != expected_record:
                    raise ValueError("reference-layout proof differs from source or native range")
                for address, relocation_type in sorted(native_relocs.items()):
                    if start <= address < start + size:
                        if kind != "code" or relocation_type != 3 or address + 4 > start + size:
                            raise ValueError("unsupported reference-layout relocation")
                        target = struct.unpack_from("<I", mapped, address - base)[0]
                        target_row = next((r for r in component["data"] if r["address"] == target), None)
                        if target_row is None:
                            raise ValueError("reference-layout target has no concrete source storage")
                        expected_relocs.append({"address": address, "type": 3, "target": target,
                                               "target_name": target_row["name"],
                                               "symbol": next((r["symbol"] for r in saved["relocations"] if r["address"] == address), None)})
            if saved["relocations"] != expected_relocs or any(
                not r["symbol"].startswith(f"?{r['target_name']}@@3") for r in saved["relocations"]
            ):
                raise ValueError("reference-layout relocation proof differs")
        path = matchlib.REPO_ROOT / saved["artifact"]
        if not path.resolve().is_relative_to(OUTPUT.resolve()) or path.name != "component.dll":
            raise ValueError("invalid reference-layout artifact path")
        # Like candidate objects, ignored local link artifacts may be absent in CI.
        # CI verifies source-bound receipts; a present PE must also pass byte proof.
        if path.is_file():
            if _sha(path.read_bytes()) != saved["artifact_sha256"]:
                raise ValueError("reference-layout artifact changed")
            if _verify_pe(path, component, saved["relocations"]) != saved["records"]:
                raise ValueError("reference-layout output proof differs")
        for field in ("artifact_sha256", "adapted_object_sha256", "reservation_sha256", "linker_sha256", "code_object_sha256"):
            if re.fullmatch("[0-9a-f]{64}", saved[field]) is None:
                raise ValueError("invalid reference-layout build fingerprint")
