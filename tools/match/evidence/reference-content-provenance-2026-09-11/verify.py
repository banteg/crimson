"""Replay the mutable-scalar audit defect against the preceding and current matchers."""

import argparse
import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
LEGACY_REVISION = "dd9e4122083ab82d99dc383b066426bcfc8f5835"
IMAGE_SHA256 = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def evaluate(module, address, literal, symbol, opcode=b"\xd9\x05"):
    image = module.load_image(module.default_image_path())
    candidate = module.ObjectFunction(
        name="_content_probe", data=opcode + b"\0" * 4 + b"\xc3",
        relocation_offsets=frozenset({len(opcode)}),
        relocation_references=(module.ObjectRelocationReference(
            offset=len(opcode), symbol_name=symbol, key=None, explained=False,
            symbol_data=literal, read_only_data=True, relocation_type=6,
        ),),
    )
    target = opcode + struct.pack("<I", address) + b"\xc3"
    result = module.match_function(
        target, candidate, image=image, target_va=0x401000,
        reference_catalog=module.load_reference_catalog(module.load_function_manifest(scope="all")),
    )
    return {
        "target_bytes": target.hex(), "candidate_bytes": candidate.data.hex(),
        "candidate_reference": asdict(candidate.relocation_references[0]),
        "ratio": result.ratio, "exact": result.exact, "body_byte_exact": result.body_byte_exact,
        "audit": asdict(result.masked_operand_audit),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    image_path = match.default_image_path()
    assert sha(image_path.read_bytes()) == IMAGE_SHA256
    git = shutil.which("git")
    assert git is not None
    old_source = subprocess.run(
        [git, "show", f"{LEGACY_REVISION}:src/crimson/match.py"],
        cwd=match.REPO_ROOT, check=True, capture_output=True,
    ).stdout
    old_path = out / "legacy_match.py"
    old_path.write_bytes(old_source)
    spec = importlib.util.spec_from_file_location("crimson._content_probe_legacy", old_path)
    legacy = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = legacy
    spec.loader.exec_module(legacy)
    # Preserve the actual repository paths when loading the historical module
    # from the reproduction output directory.
    legacy.REPO_ROOT = match.REPO_ROOT
    legacy.default_image_path = match.default_image_path
    legacy.load_function_manifest = match.load_function_manifest
    legacy.load_reference_catalog = match.load_reference_catalog
    image = match.load_image(image_path)
    catalog = match.load_reference_catalog(match.load_function_manifest(scope="all"))
    timer = catalog._addresses_for_symbol("bonus_freeze_timer")[0]
    assert timer == 0x487018
    literal = image.mapped[timer - image.image_base : timer - image.image_base + 4]
    assert literal == b"\0" * 4
    cases = [
        ("mutable-global-versus-read-only-bytes", timer, literal, "_frozen_constant", b"\xd9\x05", False),
        ("mutable-global-versus-compiler-float", timer, literal, "__real@constant", b"\xd9\x05", False),
        ("named-global-owner", timer, literal, "_bonus_freeze_timer", b"\xd9\x05", True),
        ("read-only-float-pool", 0x46F224, bytes.fromhex("0000803f"), "__real@constant", b"\xd9\x05", True),
        ("compiler-cstring-address-policy", 0x477EEC, b"music.paq\0", "??_C@literal", b"\x68", True),
    ]
    records = []
    for name, address, data, symbol, opcode, expected in cases:
        assert image.mapped[address - image.image_base : address - image.image_base + len(data)] == data
        before = evaluate(legacy, address, data, symbol, opcode)
        after = evaluate(match, address, data, symbol, opcode)
        assert before["exact"] and before["body_byte_exact"], (name, before)
        assert after["exact"] is expected and after["body_byte_exact"] is expected, (name, after)
        records.append({"name": name, "native_address": address, "before": before, "after": after})
    zlib_config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/grim_zlib_inflate_init2")
    zlib_status = match.evaluate_scratch(zlib_config)
    assert zlib_status.body_byte_exact and zlib_status.masked_ok == 7
    assert not zlib_status.masked_unresolved and not zlib_status.masked_mismatches
    zlib_reference = next(row for row in zlib_status.audit.entries if row.target_address == 0x10047452)
    assert zlib_reference.target_references[0].value == 0x1005820C
    assert zlib_reference.candidate_references[0].keys == ('string:"1.1.3"',)
    zlib_image_path = match._paths_for_image(zlib_config.image)[0]
    zlib_control = {
        "function": zlib_config.function,
        "image_sha256": sha(zlib_image_path.read_bytes()),
        "source_sha256": sha((zlib_config.directory / zlib_config.source).read_bytes()),
        "object_sha256": sha(match.compile_scratch(zlib_config).read_bytes()),
        "ratio": zlib_status.ratio,
        "body_byte_exact": zlib_status.body_byte_exact,
        "literal_reference": asdict(zlib_reference),
    }
    record = {
        "schema_version": 1, "legacy_revision": LEGACY_REVISION,
        "legacy_match_sha256": sha(old_source), "current_match_sha256": sha(Path(match.__file__).read_bytes()),
        "image_sha256": IMAGE_SHA256, "verifier_sha256": sha(Path(__file__).read_bytes()),
        "scope": "Synthetic x86 load/address callers referencing real PE data; not an execution proof of a game function.",
        "cases": records,
        "stock_zlib_literal_load_control": zlib_control,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2, default=lambda value: value.hex()) + "\n")
    print("Verified two rejected scalar substitutions, three synthetic controls, and the stock zlib literal load")


if __name__ == "__main__":
    main()
