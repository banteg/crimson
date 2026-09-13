"""Map residuals and check one closed instruction window without awarding credit."""

import argparse
import hashlib
import json
import re
from dataclasses import asdict, replace
from pathlib import Path

from recover import BEFORE_SHA, BODY_SHA, STEPS, recover

from crimson import match
from crimson.match_diagnostics import residual_summary_payload

HERE = Path(__file__).resolve().parent
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
REGIONS = (
    ("primary-projectiles", 0x420B90, 0x421A0D),
    ("secondary-projectiles", 0x421A0D, 0x42246A),
    ("sprite-effects", 0x42246A, 0x4224E8),
    ("particle-movement", 0x4224E8, 0x4226AF),
    ("particle-expiry", 0x4226AF, 0x422767),
    ("particle-steering-age", 0x422767, 0x42287D),
    ("particle-collision-attachment", 0x42287D, 0x4228E4),
    ("particle-impact-geometry", 0x4228E4, 0x4229E1),
    ("particle-damage", 0x4229E1, 0x422AB1),
    ("particle-clamp", 0x422AB1, 0x422B93),
    ("particle-effects-displacement", 0x422B93, 0x422C46),
    ("loop-epilogue", 0x422C46, 0x422C69),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def local_lines(lines):
    start = lines[0].offset
    end = lines[-1].offset + lines[-1].size
    targets = {line.offset for line in lines}
    result = []
    for line in lines:
        branch = re.fullmatch(r"(j[a-z]+) L([0-9a-f]+)", line.text)
        if branch:
            destination = int(branch[2], 16)
            if destination not in targets or not start <= destination < end:
                return None
            result.append(f"{branch[1]} W{destination - start:x}")
        else:
            result.append(line.text)
    return result


def age_window(result, body, image):
    one = bytes.fromhex("0000803f")
    target = tuple(line for line in result.target_disassembly if 0x42283F <= line.address < 0x42285D)
    assert len(target) == 9 and sum(line.size for line in target) == 30
    expected = local_lines(target)
    candidates = []
    for i in range(len(result.candidate_disassembly) - len(target) + 1):
        lines = result.candidate_disassembly[i : i + len(target)]
        if local_lines(lines) == expected:
            candidates.append(lines)
    if not candidates:
        return {"native_start": "0x42283f", "native_end": "0x42285d", "window_found": False}
    assert len(candidates) == 1
    candidate = candidates[0]
    start, end = candidate[0].offset, candidate[-1].offset + candidate[-1].size
    assert end - start == 30
    native_bytes = bytearray(image.mapped[0x42283F - image.image_base : 0x42285D - image.image_base])
    candidate_bytes = bytearray(body.data[start:end])
    compared = []
    for left, right in zip(target, candidate, strict=True):
        assert left.size == right.size
        assert left.offset - target[0].offset == right.offset - start
        assert len(left.masked_references) == len(right.masked_references)
        for a, b in zip(left.masked_references, right.masked_references, strict=True):
            assert a.explained and b.explained
            assert set(a.keys).intersection(b.keys) == {"bytes4:0000803f"}
            assert image.mapped[a.value - image.image_base : a.value - image.image_base + 4] == one
            relocations = [
                ref for ref in body.relocation_references if right.offset <= ref.offset < right.offset + right.size
            ]
            assert len(relocations) == 1
            ref = relocations[0]
            assert ref.relocation_type == match.IMAGE_REL_I386_DIR32
            assert ref.offset in body.relocation_offsets
            # COFF constant symbols gain their content key during disassembly;
            # the resolved positional references above must both be explained.
            assert ref.symbol_data[:4] == bytes.fromhex("0000803f") and ref.addend == 0
            offset = ref.offset - start
            assert offset + 4 <= right.offset - start + right.size
            native_bytes[offset : offset + 4] = b"\0" * 4
            candidate_bytes[offset : offset + 4] = b"\0" * 4
            compared.append({"offset": offset, "size": 4, "constant": "0000803f", "native_address": hex(a.value)})
    assert len(compared) == 2
    assert candidate_bytes == native_bytes
    return {
        "native_start": "0x42283f",
        "native_end": "0x42285d",
        "candidate_start": start,
        "candidate_end": end,
        "window_found": True,
        "instructions": 9,
        "bytes": 30,
        "audited_address_fields": compared,
        "remaining_encoded_bytes_equal": True,
        "masked_bytes_sha256": sha(native_bytes),
        "branches": "Both destinations stay inside this window; relative displacements are compared as encoded.",
        "scope": "Instruction-window diagnostic only. Does not establish whole-function exactness or award matching credit.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    before = (HERE / "before.cpp").read_text()
    assert sha(before.encode()) == BEFORE_SHA
    image_path = match.default_image_path()
    assert sha(image_path.read_bytes()) == IMAGE_SHA
    image = match.load_image(image_path)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    rows = []
    for count in range(len(STEPS) + 1):
        directory = args.out / str(count)
        directory.mkdir(exist_ok=True)
        source = recover(before, STEPS[:count])
        (directory / "scratch.cpp").write_text(source)
        obj = match.compile_scratch(replace(config, directory=directory))
        body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), config.symbol)
        result = match.run_match(
            obj_path=obj,
            function=config.function,
            symbol_name=config.symbol,
            reference_aliases=config.reference_aliases,
        )
        residual = residual_summary_payload(result, limit=500)
        row = {
            "steps": STEPS[:count],
            "source_sha256": sha(source.encode()),
            "body_sha256": sha(body.data),
            "object_sha256": sha(obj.read_bytes()),
            "instructions": len(result.candidate_disassembly),
            "frame": result.candidate_lines[0],
            "exact": result.exact,
            "body_byte_exact": result.body_byte_exact,
            "references_ok": result.masked_operand_audit.ok_count,
            "reference_problems": result.masked_operand_audit.problem_count,
            "residual_summary": residual["summary"],
            "reference_details": residual["reference_problems"],
            "age_window": age_window(result, body, image),
        }
        rows.append(row)
        for label, lines in (("native", result.target_disassembly), ("candidate", result.candidate_disassembly)):
            (directory / f"{label}.json").write_text(json.dumps([asdict(line) for line in lines], indent=2) + "\n")
        (directory / "residual.json").write_text(json.dumps(residual, indent=2) + "\n")
    assert rows[-1]["body_sha256"] == BODY_SHA
    assert rows[-1]["age_window"]["remaining_encoded_bytes_equal"]
    record = {
        "schema_version": 1,
        "function": "projectile_update",
        "native_image_sha256": IMAGE_SHA,
        "native_extent": {"start": "0x420b90", "end": "0x422c69", "bytes": 8409, "instructions": 2203},
        "regions": [{"name": name, "native_start": hex(start), "native_end": hex(end)} for name, start, end in REGIONS],
        "rows": rows,
        "new_exact_matches": 0,
        "caveat": "Residual spans and stack relationships are heuristic navigation, not distinct bugs or proven variable mappings. Every candidate is non-exact; canonical matching credit is unchanged.",
        "harness_sha256": {path.name: sha(path.read_bytes()) for path in (HERE / "audit.py", HERE / "recover.py")},
    }
    (args.out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("PASS", len(rows), "candidate snapshots; age window verified; no new exact functions")


if __name__ == "__main__":
    main()
