"""Prove the flags-cursor recovery changes only the native submission loop."""

import argparse
import hashlib
import json
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path

import capstone

from crimson import match

REPO = match.REPO_ROOT
SCRATCH = Path("tools/match/scratches/highscore_sync_worker")
BASE = "af9d5e1f5"
IMAGE_SHA256 = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
START, BEFORE_END, AFTER_END = 0x23C, 0x2D6, 0x2D8
BODY_HASHES = (
    "55ab40d0b8cab758f59b5efcf19b9bbcd8e7121dc9937dfae81cf0cfbc57ee14",
    "4b2b3cab6632b1147468566ffc992d9f5bf86d22085b4b1313d6630d5f3d712e",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def translate(offset):
    if offset < START:
        return offset
    if offset >= BEFORE_END:
        return offset + AFTER_END - BEFORE_END
    raise ValueError("an outside instruction or reference enters the changed window")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to load the pinned baseline")
    base_commit = subprocess.check_output(
        [git, "rev-parse", f"{BASE}^{{commit}}"], cwd=REPO, text=True,
    ).strip()
    before_source = subprocess.check_output(
        [git, "show", f"{base_commit}:{SCRATCH}/scratch.cpp"], cwd=REPO,
    )
    after_source = (REPO / SCRATCH / "scratch.cpp").read_bytes()
    image_path = match.default_image_path()
    assert sha(image_path.read_bytes()) == IMAGE_SHA256, "original image changed"
    functions, listings, configs = [], [], []
    for name, source in zip(("before", "after"), (before_source, after_source), strict=True):
        directory = out / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "scratch.cpp").write_bytes(source)
        (directory / "scratch.conf").write_bytes((REPO / SCRATCH / "scratch.conf").read_bytes())
        config = match.load_scratch_config(directory)
        listing = match.generate_compiler_listing(config, match.DEFAULT_MATCH_ROOT, output=out / f"{name}.cod")
        function = match.extract_object_function(
            match.parse_coff_object(listing.canonical_object.read_bytes()), config.symbol,
        )
        configs.append(config)
        listings.append(listing)
        functions.append(function)
    assert tuple(sha(function.data) for function in functions) == BODY_HASHES, "compiled bodies changed"

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instructions = [list(decoder.disasm(function.data, 0)) for function in functions]
    for function, rows in zip(functions, instructions, strict=True):
        assert sum(row.size for row in rows) == len(function.data), "incomplete decoding"
    outside = [
        [row for row in rows if not START <= row.address < end]
        for rows, end in zip(instructions, (BEFORE_END, AFTER_END), strict=True)
    ]
    adjusted_branches = []
    for old, new in zip(*outside, strict=True):
        assert translate(old.address) == new.address
        if old.bytes == new.bytes:
            continue
        assert old.group(capstone.CS_GRP_JUMP) and new.group(capstone.CS_GRP_JUMP)
        assert old.mnemonic == new.mnemonic and old.size == new.size
        assert len(old.operands) == len(new.operands) == 1
        assert old.operands[0].type == new.operands[0].type == capstone.x86.X86_OP_IMM
        assert translate(old.operands[0].imm) == new.operands[0].imm
        assert old.imm_offset == new.imm_offset and old.imm_size == new.imm_size
        first, second = bytearray(old.bytes), bytearray(new.bytes)
        first[old.imm_offset : old.imm_offset + old.imm_size] = bytes(old.imm_size)
        second[new.imm_offset : new.imm_offset + new.imm_size] = bytes(new.imm_size)
        assert first == second, "non-displacement branch encoding changed"
        adjusted_branches.append({
            "before_offset": old.address,
            "after_offset": new.address,
            "before_destination": old.operands[0].imm,
            "after_destination": new.operands[0].imm,
        })
    references = [
        [ref for ref in function.relocation_references if not START <= ref.offset < end]
        for function, end in zip(functions, (BEFORE_END, AFTER_END), strict=True)
    ]
    for old, new in zip(*references, strict=True):
        expected = asdict(old)
        expected["offset"] = translate(old.offset)
        assert expected == asdict(new), "outside relocation changed"

    results = [
        match.run_match(
            obj_path=listing.canonical_object,
            function=config.function,
            image_path=image_path,
            functions_path=match.default_functions_path(config.image),
            metadata_path=match.default_metadata_path(config.image),
            symbol_name=config.symbol,
            reference_aliases=config.reference_aliases,
        )
        for config, listing in zip(configs, listings, strict=True)
    ]
    assert [result.prefix_instructions for result in results] == [130, 340]
    assert all(result.masked_operand_audit.problem_count == 0 for result in results)
    assert all(not result.body_byte_exact for result in results)
    prefix = results[1].prefix_instructions
    assert results[1].target_disassembly[prefix].offset == 0x524
    assert results[1].candidate_disassembly[prefix].offset == 0x524
    prefix_references = [entry for entry in results[1].masked_operand_audit.entries if entry.target_index < prefix]
    assert all(entry.target_index == entry.candidate_index and entry.status == "ok" for entry in prefix_references)
    payload = {
        "schema": 1,
        "kind": "highscore-flags-cursor-locality-proof",
        "base_commit": base_commit,
        "image_sha256": IMAGE_SHA256,
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "source_sha256": [sha(before_source), sha(after_source)],
        "body_sha256": list(BODY_HASHES),
        "body_bytes": [len(function.data) for function in functions],
        "instruction_counts": [len(rows) for rows in instructions],
        "changed_region": {"start": START, "before_end": BEFORE_END, "after_end": AFTER_END},
        "outside_instructions": len(outside[0]),
        "outside_relocations": len(references[0]),
        "adjusted_branches": adjusted_branches,
        "native_prefix_instructions": [result.prefix_instructions for result in results],
        "prefix_positional_references": len(prefix_references),
        "resolved_references": [result.masked_operand_audit.ok_count for result in results],
        "body_byte_exact": [result.body_byte_exact for result in results],
        "verified": True,
    }
    output = out / "comparison.json"
    output.write_text(json.dumps(payload, indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    main()
