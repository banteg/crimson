"""Optional external alignments. Never feeds scores or aliases into acceptance.

COFF files are diagnostic containers, not recovered native objects. Every byte
change is independently identified and recorded alongside untouched inputs.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
from collections import Counter
from dataclasses import asdict
from importlib import metadata
from pathlib import Path
from typing import Any

from . import match as m


def digest(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def coff(code: bytes, function: str, relocations: list[dict[str, Any]]) -> bytes:
    """One exact-extent code section with named undefined external symbols."""
    names = [function] + sorted({r["symbol"] for r in relocations})
    string_table = bytearray(b"\0" * 4)
    symbols = bytearray()
    for index, name in enumerate(names):
        raw = name.encode("ascii")
        name_field = struct.pack("<II", 0, len(string_table))
        string_table.extend(raw + b"\0")
        symbols.extend(struct.pack("<8sIhHBB", name_field, 0, 1 if index == 0 else 0, 0x20 if index == 0 else 0, 2, 0))
    struct.pack_into("<I", string_table, 0, len(string_table))
    relocation_data = b"".join(
        struct.pack("<IIH", r["field_offset"], names.index(r["symbol"]), r["type"]) for r in relocations
    )
    symtab = 60 + len(code) + len(relocation_data)
    header = struct.pack("<HHIIIHH", 0x14C, 1, 0, symtab, len(names), 0, 0)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        0,
        0,
        len(code),
        60,
        60 + len(code) if relocations else 0,
        0,
        len(relocations),
        0,
        0x60000020,
    )
    output = header + section + code + relocation_data + symbols + string_table
    parsed = m.parse_coff_object(output)
    extracted = m.extract_object_function(parsed, function)
    if extracted.data != code or extracted.relocation_offsets != frozenset(r["field_offset"] for r in relocations):
        raise ValueError("Diagnostic COFF round-trip changed function bytes or relocations")
    return output


def reference_key(ref: m.MaskedReference, side: str) -> str:
    # Every emitted identity is an actual key from the independently resolved
    # operand. No instruction alignment or score participates in this choice.
    if not ref.explained:
        return f"unexplained:{side}:{ref.text}"
    priorities = ("bytes", "string:", "vc6", "address:", "name:")
    for prefix in priorities:
        keys = sorted(k for k in ref.keys if k.startswith(prefix))
        if keys:
            return keys[0]
    raise ValueError(f"Unsupported reference identity: {ref}")


def wrapper(
    raw: bytes, lines: tuple[m.DisassemblyLine, ...], side: str, name: str, candidate: m.ObjectFunction | None = None,
) -> tuple[bytes, dict[str, Any]]:
    import capstone

    if not lines or lines[0].offset != 0:
        raise ValueError("Diagnostic export requires a nonempty contiguous function body")
    body_end = lines[-1].offset + lines[-1].size
    original = raw[:body_end]
    code = bytearray(original)
    local_patches: list[dict[str, Any]] = []
    if candidate:
        for ref in candidate.relocation_references:
            if (
                ref.local_target_offset is not None
                and 0 <= ref.local_target_offset < body_end
                and ref.relocation_type == m.IMAGE_REL_I386_REL32
            ):
                before = code[ref.offset : ref.offset + 4].hex()
                struct.pack_into("<i", code, ref.offset, ref.local_target_offset - (ref.offset + 4))
                local_patches.append(
                    {
                        "offset": ref.offset,
                        "before": before,
                        "after": code[ref.offset : ref.offset + 4].hex(),
                        "target_offset": ref.local_target_offset,
                    },
                )
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    decoded = list(md.disasm(bytes(code), 0))
    if [(x.address, x.size) for x in decoded] != [(x.offset, x.size) for x in lines]:
        raise ValueError("Diagnostic bytes do not decode to the canonical instruction boundaries")
    relocations = []
    touched = set()
    for instruction_index, (insn, line) in enumerate(zip(decoded, lines, strict=True)):
        for ref in line.masked_references:
            field = insn.disp_offset if ref.kind == "disp" else insn.imm_offset
            size = insn.disp_size if ref.kind == "disp" else insn.imm_size
            if size != 4 or field <= 0:
                raise ValueError(f"Unsupported reference field at {side}+{line.offset:x}: {size} bytes")
            offset = line.offset + field
            if touched.intersection(range(offset, offset + 4)):
                raise ValueError("Overlapping diagnostic reference fields")
            touched.update(range(offset, offset + 4))
            relative = ref.kind == "imm" and (
                capstone.CS_GRP_JUMP in insn.groups or capstone.CS_GRP_CALL in insn.groups
            )
            key = reference_key(ref, side)
            readable = re.sub(r"[^a-zA-Z0-9_]", "_", key)[:48]
            symbol = f"ref_{readable}_{digest(key.encode())[:16]}"
            relocations.append(
                {
                    "instruction_index": instruction_index,
                    "instruction_offset": line.offset,
                    "operand_index": ref.operand_index,
                    "kind": ref.kind,
                    "field_offset": offset,
                    "type": 0x14 if relative else 6,
                    "symbol": symbol,
                    "identity": key,
                    "evidence": asdict(ref),
                    "before": code[offset : offset + 4].hex(),
                },
            )
            code[offset : offset + 4] = b"\0" * 4
    # Byte-preservation witness for all non-reference/non-local-relocation bytes.
    patch_bytes = touched | {p["offset"] + i for p in local_patches for i in range(4)}
    if not all(a == b for i, (a, b) in enumerate(zip(original, code, strict=True)) if i not in patch_bytes):
        raise ValueError("Diagnostic export changed an instruction byte outside recorded reference fields")
    payload = {
        "raw_sha256": digest(raw),
        "body_sha256": digest(original),
        "wrapped_code_sha256": digest(code),
        "body_size": body_end,
        "excluded_terminal_bytes": len(raw) - body_end,
        "instructions": [asdict(x) for x in lines],
        "relocations": relocations,
        "local_relative_patches": local_patches,
    }
    return coff(bytes(code), name, relocations), payload


def export_scratch(directory: Path, output: Path, match_root: Path, scope: str) -> None:
    config = m.load_scratch_config(directory.resolve())
    obj = m.compile_scratch(config, match_root)
    full_obj = obj.read_bytes()
    candidate = m.extract_object_function(
        m.parse_coff_object(full_obj),
        config.symbol,
        extent=config.archive_extent,
        end_symbol=config.archive_end_symbol,
        size=config.archive_size,
    )
    result = m.run_match(
        obj_path=obj,
        function=config.function,
        image_path=m.default_image_path(config.image),
        functions_path=m.default_functions_path(config.image),
        metadata_path=m.default_metadata_path(config.image),
        symbol_name=config.symbol,
        object_extent=config.archive_extent,
        object_end_symbol=config.archive_end_symbol,
        object_size=config.archive_size,
        end_va=config.end_va,
        reference_aliases=config.reference_aliases,
        scope=scope,
    )
    image = m.load_image(m.default_image_path(config.image))
    start = result.target_disassembly[0].address
    end = start + result.target_disassembly[-1].offset + result.target_disassembly[-1].size
    target = image.mapped[start - image.image_base : end - image.image_base]
    output.mkdir(parents=True, exist_ok=False)
    (output / "compiler-original.obj").write_bytes(full_obj)
    if config.archive is None and config.import_thunk is None:
        (output / "scratch-source.txt").write_bytes((config.directory / config.source).read_bytes())
    (output / "scratch.conf").write_bytes((config.directory / "scratch.conf").read_bytes())
    provenance = {
        "config": asdict(config),
        "scope": scope,
        "build_inputs": m._scratch_build_key(config, match_root),
        "diagnostic_module_sha256": {
            name: digest(Path(__file__).with_name(name).read_bytes())
            for name in ("match_explain.py", "match_address_diagnostics.py")
        },
        "compiler_object_path": str(obj),
        "compiler_object_sha256": digest(full_obj),
        "image_sha256": digest(m.default_image_path(config.image).read_bytes()),
    }
    write_json(output / "provenance.json", json.loads(json.dumps(provenance, default=str)))
    for side, raw, lines, original in (
        ("target", target, result.target_disassembly, None),
        ("candidate", candidate.data, result.candidate_disassembly, candidate),
    ):
        (output / f"{side}-original.bin").write_bytes(raw)
        wrapped, evidence = wrapper(raw, lines, side, "diagnostic_function", original)
        (output / f"{side}.obj").write_bytes(wrapped)
        write_json(output / f"{side}-evidence.json", evidence)
    canonical = m.match_result_payload(result)
    canonical["reference_audit_entries"] = [asdict(e) for e in result.masked_operand_audit.entries]
    write_json(output / "crimson.json", canonical)


def resolve_asm_differ(path: Path | None) -> Path:
    if path is None:
        try:
            path = Path(str(metadata.distribution("asm-differ").locate_file("diff.py")))
        except metadata.PackageNotFoundError as exc:
            raise ValueError(
                "Install the optional group with uv sync --group match-explain, or pass --asm-differ",
            ) from exc
    if not path.is_file():
        raise ValueError(f"asm-differ script not found: {path}")
    return path.resolve()


def executable(value: str) -> str:
    found = shutil.which(value)
    if found is None:
        raise ValueError(f"Executable not found: {value}. See docs/re/diagnostic-alignments.md for optional setup.")
    return str(Path(found).absolute())


def run_json(args: list[str], cwd: Path):
    try:
        completed = subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True, timeout=180)
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"{args[0]} failed: {exc.stderr.strip() or exc.stdout.strip()}") from exc
    return json.loads(completed.stdout)


def alignment_offsets(payload, engine: str):
    if engine == "objdiff":
        functions = []
        for side in ("left", "right"):
            symbols = [s for s in payload[side]["symbols"] if s.get("kind") == "SYMBOL_FUNCTION"]
            if len(symbols) != 1:
                raise ValueError(f"Expected one diagnostic function on {side}")
            functions.append(symbols[0]["instructions"])
        return [
            tuple(int(ins["instruction"].get("address", 0)) if ins.get("instruction") else None for ins in pair)
            for pair in zip(*functions, strict=True)
        ]
    return [
        tuple(row[side].get("line") if row.get(side) else None for side in ("base", "current"))
        for row in payload["rows"]
        if not row.get("is_data_ref")
    ]


def paired_rows(offsets, evidence):
    lookup = {s: {i["offset"]: i for i in evidence[s]["instructions"]} for s in ("target", "candidate")}
    # Counts alone miss duplicate or reordered instructions. Require each exact
    # offset once, in original order, including instructions the tool leaves unpaired.
    for index, side in enumerate(("target", "candidate")):
        actual = [pair[index] for pair in offsets if pair[index] is not None]
        if actual != list(lookup[side]):
            raise ValueError(f"Incomplete, reordered or duplicate {side} instruction coverage")
    rows = []
    for left, right in offsets:
        a, b = lookup["target"].get(left), lookup["candidate"].get(right)
        refs_a = tuple(m.MaskedReference(**v) for v in a["masked_references"]) if a else ()
        refs_b = tuple(m.MaskedReference(**v) for v in b["masked_references"]) if b else ()
        status = m._masked_reference_status(refs_a, refs_b) if refs_a or refs_b else None
        rows.append({"target": a, "candidate": b, "reference_status": status})
    return rows


def compare_bundle(output: Path, *, engine: str, objdiff: str, asm_differ: Path | None, asm_python: str, objdump: str):
    """Run on an exported bundle, retaining raw tool output and checked rows."""
    output = output.resolve()
    evidence = {s: json.loads((output / f"{s}-evidence.json").read_text()) for s in ("target", "candidate")}
    target, candidate = output / "target.obj", output / "candidate.obj"
    engines = ("objdiff", "levenshtein") if engine == "both" else (engine,)
    reports = {}
    versions = {}
    for name in engines:
        if name == "objdiff":
            binary = executable(objdiff)
            versions[name] = {
                "path": binary,
                "sha256": digest(Path(binary).read_bytes()),
                "version": subprocess.check_output([binary, "--version"], text=True, timeout=10).strip(),
            }

            def run(right, binary=binary):
                return run_json(
                    [binary, "diff", "-1", str(target), "-2", str(right), "-o", "-", "--format", "json"],
                    output,
                )
        else:
            script = resolve_asm_differ(asm_differ)
            python = executable(asm_python)
            dump = executable(objdump)
            versions[name] = {
                "script": str(script),
                "sha256": digest(script.read_bytes()),
                "python": python,
                "objdump": dump,
                "objdump_version": subprocess.check_output([dump, "--version"], text=True, timeout=10).splitlines()[0],
            }
            settings = {
                "arch": "i686",
                "objdump_executable": dump,
                "objdump_flags": ["-b", "pe-i386"],
                "build_dir": ".",
            }
            (output / "diff_settings.py").write_text(
                "def apply(config, args):\n    config.update(" + repr(settings) + ")\n",
            )

            def run(right, python=python, script=script):
                return run_json(
                    [
                        python,
                        str(script),
                        "diagnostic_function",
                        "-o",
                        "-f",
                        str(right),
                        "-F",
                        str(target),
                        "--format",
                        "json",
                        "--max-lines",
                        "1000000",
                        "--algorithm",
                        "levenshtein",
                    ],
                    output,
                )

        raw = run(candidate)
        control = run(target)
        write_json(output / f"{name}-raw.json", raw)
        write_json(output / f"{name}-self.json", control)
        self_offsets = alignment_offsets(control, name)
        paired_rows(self_offsets, {"target": evidence["target"], "candidate": evidence["target"]})
        if any(a != b for a, b in self_offsets):
            raise ValueError(f"{name} self-comparison changed instruction pairing")
        if name == "levenshtein" and control["current_score"] != 0:
            raise ValueError("Levenshtein self-comparison has nonzero penalty")
        if name == "objdiff" and any(
            row.get("diff_kind", "DIFF_NONE") != "DIFF_NONE"
            for side in ("left", "right")
            for symbol in control[side]["symbols"]
            for row in symbol.get("instructions", [])
        ):
            raise ValueError("objdiff self-comparison reports changes")
        rows = paired_rows(alignment_offsets(raw, name), evidence)
        write_json(output / f"{name}-rows.json", rows)
        reports[name] = rows
        lines = [
            "Diagnostic pairing only; reference agreement does not prove value or control-flow correspondence.",
            "",
        ]
        for index, row in enumerate(rows):
            sides = [
                f"{row[s]['address']:08x} +{row[s]['offset']:04x} {row[s]['text']}" if row[s] else "-"
                for s in ("target", "candidate")
            ]
            lines.append(f"{index:5} | {sides[0]} | {sides[1]} | {row['reference_status'] or ''}")
        (output / f"{name}-assembly.txt").write_text("\n".join(lines) + "\n")
    write_json(output / "tools.json", versions)
    disagreements = []
    if len(reports) == 2:
        maps = {
            n: {
                r["target"]["offset"]: r["candidate"]["offset"] if r["candidate"] else None for r in rows if r["target"]
            }
            for n, rows in reports.items()
        }
        disagreements = [
            {"target_offset": a, **{n: pairs[a] for n, pairs in maps.items()}}
            for a in maps["objdiff"]
            if maps["objdiff"][a] != maps["levenshtein"][a]
        ]
    summary = {
        "diagnostic_only": True,
        "engines": list(reports),
        "reference_counts": {
            n: dict(Counter(r["reference_status"] for r in rows if r["reference_status"]))
            for n, rows in reports.items()
        },
        "alignment_disagreements": disagreements,
    }
    from .match_address_diagnostics import hypotheses

    raw_code = {
        side: m.extract_object_function(
            m.parse_coff_object((output / f"{side}.obj").read_bytes()),
            "diagnostic_function",
        ).data
        for side in evidence
    }
    summary["address_hypotheses"] = {name: hypotheses(rows, raw_code) for name, rows in reports.items()}
    write_json(output / "summary.json", summary)
    prose = [
        "# Diagnostic alignments",
        "",
        "No scores or hypotheses from this report affect native acceptance.",
        "",
        f"Reference counts: `{summary['reference_counts']}`",
        "",
        (f"Aligners disagree at {len(disagreements)} target instruction offsets. See summary.json for every pair."
         if len(reports) == 2 else "Single alignment view; use --engine both to compare proposed pairings."),
        "",
    ]
    for name, groups in summary["address_hypotheses"].items():
        for group in groups:
            prose.extend(
                [
                    f"## {name}: retained index hypothesis",
                    "",
                    group["claim"],
                    "",
                    *["- " + assumption for assumption in group["assumptions"]],
                    "",
                    group["prediction"],
                    "",
                ],
            )
            prose.append(
                f"Call origins: target +{group['origin']['target']['offset']:x}, "
                f"candidate +{group['origin']['candidate']['offset']:x}.",
            )
            prose.extend(["", "Affine values below are `(index coefficient, constant)` modulo 2^32.", ""])
            for side, definitions in group["definitions"].items():
                for item in definitions:
                    prose.append(
                        f"- {side} +{item['offset']:x}: `{item['instruction']}` -> "
                        f"`{item['register']} = {item['affine']}`",
                    )
            prose.extend(["", "Related memory operands:", ""])
            for use in group["uses"]:
                prose.append(
                    f"- Target +{use['target']['offset']:x} / candidate +{use['candidate']['offset']:x}: "
                    f"`{use['target']['affine']}`; "
                    f"{use['target']['retained_registers']} vs {use['candidate']['retained_registers']}",
                )
            prose.append("")
    (output / "README.md").write_text("\n".join(prose) + "\n")
    return summary
