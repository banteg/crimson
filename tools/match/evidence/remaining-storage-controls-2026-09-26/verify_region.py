"""Check K2's encoded bytes, masking only its two verified DIR32 references."""

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
START, STOP = 0x325, 0x371
OFFSETS = (0x327, 0x353)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def equivalent(native, candidate, references):
    if len(native) != STOP - START or len(candidate) != len(native):
        return False
    if [r.offset for r in references] != list(OFFSETS):
        return False
    expected = ("_grim_interface_ptr", "name:grim_interface_ptr", True, 0, 6)
    if any((r.symbol_name, r.key, r.explained, r.addend, r.relocation_type) != expected for r in references):
        return False
    left, right = bytearray(native), bytearray(candidate)
    for offset in OFFSETS:
        i = offset - START
        if int.from_bytes(left[i : i + 4], "little") != 0x48083C or right[i : i + 4] != bytes(4):
            return False
        left[i : i + 4] = right[i : i + 4] = bytes(4)
    return left == right


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    controls = json.loads((HERE / "controls.json").read_text())
    selected = next(c for c in controls["targets"]["projectile_render"]["controls"] if c["name"] == "tint_copy")
    config = match.load_scratch_config(args.scratch)
    assert sha((args.scratch / config.source).read_bytes()) == selected["source_sha256"]
    assert sha(match.default_image_path().read_bytes()) == controls["image_sha256"]
    obj = match.compile_scratch(config)
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), config.symbol)
    assert sha(body.data) == selected["body_sha256"]
    image = match.load_image(match.default_image_path())
    native = image.function_bytes(0x422C70, 0x425D77)[START:STOP]
    candidate = body.data[START:STOP]
    references = [r for r in body.relocation_references if START <= r.offset < STOP]
    assert equivalent(native, candidate, references)
    wrong_alpha = bytearray(candidate)
    wrong_alpha[0x32F - START] = 1
    wrong_slot = bytearray(candidate)
    wrong_slot[0x336 - START] = 0x18
    wrong_refs = [replace(references[0], key="name:transition_alpha"), references[1]]
    assert not equivalent(native, wrong_alpha, references)
    assert not equivalent(native, wrong_slot, references)
    assert not equivalent(native, candidate, wrong_refs)
    receipt = {
        "source_sha256": selected["source_sha256"],
        "body_sha256": sha(body.data),
        "image_sha256": controls["image_sha256"],
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "native_extent": ["0x422f95", "0x422fe1"],
        "candidate_extent": [hex(START), hex(STOP)],
        "instructions": 18,
        "bytes": len(native),
        "native_hex": native.hex(),
        "candidate_hex": candidate.hex(),
        "masked_fields": [
            {"offset": hex(o), "width": 4, "kind": "DIR32", "symbol": "grim_interface_ptr"} for o in OFFSETS
        ],
        "negative_controls_rejected": ["nonzero-alpha", "wrong-load-slot", "wrong-reference"],
        "full_function_exact": False,
        "full_function_body_byte_exact": False,
    }
    args.out.write_text(json.dumps(receipt, indent=2) + "\n")
    print("K2: 76 bytes agree with two verified relocation fields; three negative controls rejected")


if __name__ == "__main__":
    main()
