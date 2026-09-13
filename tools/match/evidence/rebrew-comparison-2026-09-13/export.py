"""Freeze native/candidate bodies; resolve references independently of Rebrew alignment."""

import argparse
import hashlib
import json
import shutil
import struct
from dataclasses import asdict, replace
from pathlib import Path

from crimson import match as m
from crimson import match_diagnostics, match_flow_graph


def sha(data):
    return hashlib.sha256(data).hexdigest()


def export(name, root):
    out = root / name
    out.mkdir()
    config = m.load_scratch_config(m.DEFAULT_MATCH_ROOT / "scratches" / name)
    shutil.copytree(config.directory, out / "source", ignore=shutil.ignore_patterns("build", "__pycache__"))
    frozen = replace(config, directory=out / "source")
    obj = m.compile_scratch(frozen, force=True)
    raw = obj.read_bytes()
    candidate = m.extract_object_function(
        m.parse_coff_object(raw),
        config.symbol,
        extent=config.archive_extent,
        end_symbol=config.archive_end_symbol,
        size=config.archive_size,
    )
    result = m.run_match(
        obj_path=obj, function=config.function, symbol_name=config.symbol, reference_aliases=config.reference_aliases,
    )
    image = m.load_image(m.default_image_path(config.image))
    start = result.target_disassembly[0].address
    end = result.target_disassembly[-1].address + result.target_disassembly[-1].size
    target = image.mapped[start - image.image_base : end - image.image_base]
    candidate_end = result.candidate_disassembly[-1].offset + result.candidate_disassembly[-1].size
    compiled = bytearray(candidate.data[:candidate_end])
    # Use all native reference identities, without pairing instructions.
    values = {}
    for line in result.target_disassembly:
        for ref in line.masked_references:
            if ref.explained and ref.value is not None:
                for key in ref.keys:
                    values.setdefault(key, set()).add(ref.value)
    patches = []
    unresolved = []
    for rel in candidate.relocation_references:
        if rel.offset >= len(compiled):
            continue
        address = None
        if rel.local_target_offset is not None:
            address = start + rel.local_target_offset
        else:
            line = next((l for l in result.candidate_disassembly if l.offset <= rel.offset < l.offset + l.size), None)
            refs = (
                []
                if line is None
                else [r for r in line.masked_references if r.source == "reloc" and r.text == rel.symbol_name]
            )
            keys = {k for ref in refs for k in ref.keys if ref.explained}
            direct = {int(k.split(":", 1)[1], 16) for k in keys if k.startswith("address:")}
            targets = set.union(*(values.get(k, set()) for k in keys)) if keys else set()
            choices = direct or targets
            if len(choices) == 1:
                address = next(iter(choices))
        if address is None:
            unresolved.append(asdict(rel))
            continue
        before = compiled[rel.offset : rel.offset + 4].hex()
        if rel.relocation_type == m.IMAGE_REL_I386_REL32:
            value = (address - (start + rel.offset + 4)) & 0xFFFFFFFF
        elif rel.relocation_type == m.IMAGE_REL_I386_DIR32:
            value = address & 0xFFFFFFFF
        else:
            unresolved.append(asdict(rel))
            continue
        struct.pack_into("<I", compiled, rel.offset, value)
        patches.append(
            {
                "offset": rel.offset,
                "symbol": rel.symbol_name,
                "address": address,
                "before": before,
                "after": compiled[rel.offset : rel.offset + 4].hex(),
            },
        )
    (out / "compiler.obj").write_bytes(raw)
    (out / "target.bin").write_bytes(target)
    (out / "candidate-original.bin").write_bytes(candidate.data)
    (out / "candidate-resolved.bin").write_bytes(compiled)
    payload = m.match_result_payload(result)
    payload["residual_summary"] = match_diagnostics.residual_summary_payload(result, limit=30)
    payload["flow_graph"] = match_flow_graph.flow_graph_payload(result)
    (out / "crimson.json").write_text(json.dumps(payload, indent=2) + "\n")
    evidence = {
        "va": start,
        "source_sha256": sha((config.directory / config.source).read_bytes()),
        "object_sha256": sha(raw),
        "target_sha256": sha(target),
        "candidate_sha256": sha(compiled),
        "patches": patches,
        "unresolved": unresolved,
        "crimson_exact": result.exact,
        "crimson_body_byte_exact": result.body_byte_exact,
        "crimson_ratio": result.ratio,
        "clean_references": result.masked_operand_audit.ok_count,
        "reference_problems": result.masked_operand_audit.problem_count,
        "candidate_terminal_bytes_excluded": len(candidate.data) - candidate_end,
        "resolved_bytes_equal": target == compiled,
    }
    if result.body_byte_exact:
        assert target == compiled, "Exact control must survive independent relocation materialization"
    (out / "inputs.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(name, result.ratio, "unresolved", len(unresolved), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    for name in ("quest_spawn_timeline_update", "projectile_render", "statistics_update_check_worker"):
        export(name, args.out)
