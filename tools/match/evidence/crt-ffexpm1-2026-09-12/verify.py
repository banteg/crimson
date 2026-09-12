"""Verify the VC6 ffexpm1 extent, constant identity, and encoded native body."""

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from crimson import match
from crimson.library_match import parse_coff_archive

HERE = Path(__file__).resolve().parent
ARCHIVE_SHA = "a541c95e5ffdd6d5573d1976f5e5d0038f2c4fb0bcb02975c68948bf1d6e452a"
MEMBER_SHA = "451333e5109ecc35936b19d10dd9ff0508fd869fd5b120c2df5827c2c4a85d36"
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
START, END = 0x00464E4E, 0x00464E91
CONSTANT_VA = 0x0047B67E


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/crt_ffexpm1")
    assert config.symbol == "__ffexpm1" and config.archive_size == END - START == 67
    archive = match._scratch_archive_path(config).read_bytes()
    assert sha(archive) == config.archive_sha256 == ARCHIVE_SHA
    members = [m for m in parse_coff_archive(archive) if m.name == config.archive_member]
    assert len(members) == 1 and sha(members[0].data) == MEMBER_SHA
    obj = match.parse_coff_object(members[0].data)
    symbol = next(s for s in obj.symbols if s.name == config.symbol)
    assert symbol.value == 0x15E and symbol.section_number == 1

    # This boundary predates the scratch and is not inferred from its score.
    raw = json.loads(match.DEFAULT_FUNCTIONS_PATH.read_text())
    native = next(r for r in raw if int(r["address"], 16) == START)
    following = next(r for r in raw if int(r["address"], 16) == END)
    assert native["name"] == "__ffexpm1" and int(native["end"], 16) == END
    assert native["size"] == 67 and following["name"] == "_isintTOS"
    image_bytes = match.default_image_path().read_bytes()
    assert sha(image_bytes) == IMAGE_SHA
    manifest = match.load_function_manifest(scope="all")
    image = match.load_image(match.default_image_path(), manifest.image_base)
    target = image.mapped[START - image.image_base : END - image.image_base]
    assert len(target) == 67 and target[-1] == 0xC3

    constant = next(s for s in obj.symbols if s.name == "_log2max")
    assert constant.storage_class == 3 and constant.value == 0x1E
    assert constant.section_number == 2
    original_constant = obj.sections[1].data[constant.value : constant.value + 10]
    native_constant = image.mapped[CONSTANT_VA - image.image_base : CONSTANT_VA - image.image_base + 10]
    assert original_constant == native_constant == bytes.fromhex("000000000000ffff0d40")
    data_rows = json.loads(match.DEFAULT_DATA_MAP_PATH.read_text())["entries"]
    data_row = next(r for r in data_rows if r["program"] == "crimsonland.exe" and r["name"] == "crt_x87_log2max")
    assert int(data_row["address"], 16) == CONSTANT_VA
    assert data_row["type"] == "unsigned char[10]" and "_log2max" in data_row["aliases"]

    object_path = match.compile_scratch(config, force=True)
    assert sha(object_path.read_bytes()) == MEMBER_SHA
    candidate = match.extract_object_function(obj, config.symbol, size=config.archive_size)
    whole_symbol = match.extract_object_function(obj, config.symbol)
    assert len(whole_symbol.data) > 67 and whole_symbol.data[:67] == candidate.data
    catalog = match.load_reference_catalog(manifest)

    def compare(function):
        return match.match_function(target, function, image=image, target_va=START, reference_catalog=catalog)

    result = compare(candidate)
    assert result.exact and result.body_byte_exact
    assert len(result.target_lines) == len(result.candidate_lines) == result.prefix_instructions == 24
    assert result.masked_operand_audit.ok_count == 2 and result.masked_operand_audit.problem_count == 0
    constant_access = result.masked_operand_audit.entries[0]
    assert constant_access.target_offset == 4 and "fld tword" in constant_access.instruction
    assert constant_access.target_references[0].value == CONSTANT_VA
    assert constant_access.candidate_references[0].text == "_log2max"

    # Negative controls distinguish identity from merely selecting similar code.
    extra_tail = compare(match.extract_object_function(obj, config.symbol, size=69))
    bad_return = compare(replace(candidate, data=candidate.data[:-1] + b"\xcb"))
    refs = list(candidate.relocation_references)
    index = next(i for i, r in enumerate(refs) if r.symbol_name == "_log2max")
    refs[index] = replace(
        refs[index], symbol_name="unproven_constant", key=None, explained=False, alternate_keys=(), symbol_data=None,
    )
    bad_reference = compare(replace(candidate, relocation_references=tuple(refs)))
    for rejected in (extra_tail, bad_return, bad_reference):
        assert not rejected.exact and not rejected.body_byte_exact
    assert bad_reference.masked_operand_audit.problem_count == 1
    changed_constant = bytes([original_constant[0] ^ 1]) + original_constant[1:]
    assert changed_constant != native_constant

    receipt = {
        "verified": True,
        "archive_sha256": ARCHIVE_SHA,
        "archive_member": config.archive_member,
        "member_sha256": MEMBER_SHA,
        "native_image_sha256": IMAGE_SHA,
        "native_manifest_sha256": sha(match.DEFAULT_FUNCTIONS_PATH.read_bytes()),
        "native_extent": native,
        "next_native_function": following,
        "archive_symbol": {
            "name": symbol.name,
            "offset": symbol.value,
            "unsliced_bytes": len(whole_symbol.data),
            "selected_bytes": len(candidate.data),
        },
        "native_body_sha256": sha(target),
        "constant": {
            "name": constant.name,
            "archive_section": ".data",
            "archive_offset": constant.value,
            "native_address": hex(CONSTANT_VA),
            "size": 10,
            "bytes": original_constant.hex(),
            "sha256": sha(original_constant),
        },
        "match": match.match_result_payload(result),
        "negative_controls_rejected": [
            "extra_private_helper_bytes",
            "changed_return_opcode",
            "unknown_constant_identity",
            "changed_constant_bytes",
        ],
        "config_sha256": sha((config.directory / "scratch.conf").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "limitations": "Archive-backed encoded identity; no source-built code credit or gameplay-scope change. "
        "The helper retains its native branch into neighboring CRT code; subsequent private helpers are not credited.",
    }
    (out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Verified 24 instructions, 67 encoded bytes, 2 references, the 10-byte constant, and 4 negative controls")


if __name__ == "__main__":
    main()
