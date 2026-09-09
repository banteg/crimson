"""Join checked HUD stack accesses to saved native ESP facts and compile VC6 controls."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import capstone
import pefile

from crimson import match
from crimson.match_diagnostics import _residual_alignment, _slots
from crimson.match_listing_diagnostics import (
    _normal_displacement,
    parse_stack_listing,
    stack_local_observations_payload,
)

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/ui_render_hud")
    listing = match.generate_compiler_listing(config, output=out / "hud.cod")
    result = match.run_match(
        obj_path=listing.canonical_object,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    observations = stack_local_observations_payload(
        result,
        (out / "hud.cod").read_text(),
        symbol=config.symbol,
        limit=2048,
    )
    pairs, ambiguous, remaining = _residual_alignment(result.target_lines, result.candidate_lines)
    assert len(pairs) == len(result.target_lines) == len(result.candidate_lines) == 1824
    assert not ambiguous and not remaining
    assert result.masked_operand_audit.problem_count == 0
    assert not result.exact and not result.body_byte_exact
    assert not observations["skipped"] and not any(observations["omitted_entries"].values())
    native = json.loads((HERE / "native-stack.json").read_text())
    image_bytes = match.default_image_path().read_bytes()
    image = pefile.PE(data=image_bytes)
    native_bytes = image.get_data(native["start"] - image.OPTIONAL_HEADER.ImageBase, 7081)
    assert sha(native_bytes) == native["body_sha256"]
    stack = dict(native["instruction_offsets_and_entry_esp"])
    assert len(stack) == len(native["instruction_offsets_and_entry_esp"])
    locals_ = []
    used = set()
    for section in ("locals", "unnamed_frame_accesses", "unannotated_accesses"):
        for row in observations[section]:
            assert not row["omitted_accesses"]
            accesses = []
            for access in row["accesses"]:
                target = access["target"]
                slots = _slots(target["text"])
                assert len(slots) == 1
                base, displacement = _normal_displacement(slots[0])
                assert base == "esp"
                entry_esp = stack[target["offset"]]
                used.add(target["offset"])
                accesses.append(
                    {
                        "native_offset": target["offset"],
                        "candidate_offset": access["candidate"]["offset"],
                        "native_entry_esp": entry_esp,
                        "native_displacement": displacement,
                        "native_entry_slot": entry_esp + displacement,
                        "source_lines": access["source_lines"],
                    },
                )
            locals_.append(
                {
                    "candidate_name": row["name"],
                    "kind": row["kind"],
                    "candidate_listing_declaration": row["listing_frame_offset"],
                    "native_entry_slots": sorted({a["native_entry_slot"] for a in accesses}),
                    "accesses": accesses,
                },
            )
    assert used == set(stack)

    # Small compiler examples are controls, not reconstructions of native HUD source.
    shutil.copyfile(HERE / "lifetimes.cpp", out / "lifetimes.cpp")
    environment = dict(os.environ, MSVC_VER=config.compiler)
    environment.pop("CRIMSON_MATCH_INCLUDE_OVERLAY", None)
    command = [
        str(match.DEFAULT_MATCH_ROOT / "cl.sh"),
        "/c",
        "/O2",
        "/GB",
        "/W3",
        "/GR-",
        "/FAsc",
        "/Falifetimes.cod",
        "lifetimes.cpp",
    ]
    subprocess.run(command, cwd=out, env=environment, capture_output=True, text=True, check=True)
    obj = match.parse_coff_object((out / "lifetimes.obj").read_bytes())
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    controls = []
    for name, frame in (("outer", 24), ("split", 8), ("shared", 16)):
        function = match.extract_object_function(obj, f"_{name}")
        decoded = list(decoder.disasm(function.data, 0))
        assert sum(row.size for row in decoded) == len(function.data)
        assert decoded[0].mnemonic == "sub" and decoded[0].operands[0].reg == capstone.x86.X86_REG_ESP
        assert decoded[0].operands[1].imm == frame
        declarations, _ = parse_stack_listing((out / "lifetimes.cod").read_text(), symbol=f"_{name}")
        assert [ref.symbol_name for ref in function.relocation_references] == ["_observe"] * 3
        controls.append(
            {
                "function": name,
                "frame_bytes": frame,
                "body_bytes": len(function.data),
                "instructions": len(decoded),
                "body_sha256": sha(function.data),
                "compiler_declarations": declarations,
            },
        )
    payload = {
        "schema": 1,
        "kind": "hud-observed-stack-use-map",
        "verified": True,
        "caveat": "Candidate names label paired accesses, not original variables. Saved BN ESP facts are analyzer evidence. "
        "Observed use spans are not CFG live ranges; shared slots do not prove shared source objects. "
        "Micro examples demonstrate this compiler only, not original HUD source or general program equivalence.",
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "native_stack_sha256": sha((HERE / "native-stack.json").read_bytes()),
        "image_sha256": sha(image_bytes),
        "native_body_sha256": sha(native_bytes),
        "source_sha256": sha((config.directory / config.source).read_bytes()),
        "control_source_sha256": sha((HERE / "lifetimes.cpp").read_bytes()),
        "compiler_sha256": sha(match._compiler_executable_path(config, match.DEFAULT_MATCH_ROOT).read_bytes()),
        "match": observations["match"],
        "paired_stack_instructions": len(used),
        "locals": locals_,
        "micro_controls": controls,
    }
    (out / "comparison.json").write_text(json.dumps(payload, indent=2) + "\n")
    print(out / "comparison.json")


if __name__ == "__main__":
    main()
