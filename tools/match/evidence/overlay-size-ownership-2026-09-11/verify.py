"""Verify overlay size ownership with machine calls and observed native frame slots."""

import argparse
import json
import re
from dataclasses import replace
from pathlib import Path

import fixtures
import observe

from crimson.match_diagnostics import _slots
from crimson.match_listing_diagnostics import _normal_displacement, stack_local_observations_payload

HERE = Path(__file__).resolve().parent
match, sha = observe.match, observe.sha
CHECKED = ("calls", "writes", "distance_bits", "player_state_sha256", "creature_state_sha256")


def metrics(program):
    result = program.result
    return {
        "source_sha256": sha((program.config.directory / program.config.source).read_bytes()),
        "ratio": result.ratio,
        "candidate_instructions": len(result.candidate_lines),
        "target_instructions": len(result.target_lines),
        "prefix": result.prefix_instructions,
        "references_ok": result.masked_operand_audit.ok_count,
        "reference_problems": result.masked_operand_audit.problem_count,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
        "object_sha256": sha(program.object_path.read_bytes()),
        "body_sha256": sha(program.body.data),
        "relocations": program.relocations,
    }


def merge_stack(destination, source):
    for offset, value in source.items():
        assert offset not in destination or destination[offset] == value
        destination[offset] = value


def stack_map(program, native_stack, candidate_stack, out):
    config = program.config
    match.generate_compiler_listing(config, output=out)
    observations = stack_local_observations_payload(
        program.result, out.read_text(), symbol=config.symbol, limit=2048,
    )
    assert not any(observations["omitted_entries"].values())
    rows, non_esp = [], []
    for section in ("locals", "unnamed_frame_accesses", "unannotated_accesses"):
        for row in observations[section]:
            assert not row["omitted_accesses"]
            accesses = []
            for access in row["accesses"]:
                native, candidate = access["target"], access["candidate"]
                native_slots, candidate_slots = _slots(native["text"]), _slots(candidate["text"])
                assert len(native_slots) == len(candidate_slots) == 1
                native_base, native_displacement = _normal_displacement(native_slots[0])
                candidate_base, candidate_displacement = _normal_displacement(candidate_slots[0])
                if native_base != "esp" or candidate_base != "esp":
                    assert native_base == candidate_base
                    non_esp.append(access)
                    continue
                ni, ci = native["offset"], candidate["offset"]
                assert ni in native_stack and ci in candidate_stack, (ni, ci)
                accesses.append({
                    "native_offset": ni, "candidate_offset": ci,
                    "native_entry_esp": native_stack[ni], "candidate_entry_esp": candidate_stack[ci],
                    "native_entry_slot": native_stack[ni] + native_displacement,
                    "candidate_entry_slot": candidate_stack[ci] + candidate_displacement,
                    "source_lines": access["source_lines"],
                })
            rows.append({
                "candidate_name": row["name"], "kind": row["kind"],
                "native_entry_slots": sorted({a["native_entry_slot"] for a in accesses}),
                "candidate_entry_slots": sorted({a["candidate_entry_slot"] for a in accesses}),
                "accesses": accesses,
            })
    return {
        "locals": rows,
        "non_esp_accesses": non_esp,
        "unpaired_or_ambiguous": observations["skipped"],
        "mismatches": sum(a["native_entry_slot"] != a["candidate_entry_slot"] for r in rows for a in r["accesses"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert observe.parent.unicorn.__version__ == "2.1.4"
    assert sha(match.default_image_path().read_bytes()) == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/player_render_overlays")
    before_dir = out / "before"
    before_dir.mkdir(exist_ok=True)
    before_source = (HERE / "before.cpp").read_bytes()
    assert sha(before_source) == "6b8b8274afee4c30765b527b19b87ef019423e218bf151d6a292662f13800986"
    (before_dir / config.source).write_bytes(before_source)
    programs = {"before": observe.Program(replace(config, directory=before_dir)), "current": observe.Program(config)}
    current = programs["current"]
    decoder = observe.parent.capstone.Cs(observe.parent.capstone.CS_ARCH_X86, observe.parent.capstone.CS_MODE_32)
    instructions = {
        name: list(decoder.disasm(observe.parent.linked_body(program), 0))
        for name, program in programs.items()
    }
    stack_operand = re.compile(r"\[esp(?:\s*[+-]\s*(?:0x[0-9a-f]+|\d+))?\]")
    changed_instructions = []
    for before, after in zip(instructions["before"], instructions["current"], strict=True):
        assert before.address == after.address and before.size == after.size
        assert before.mnemonic == after.mnemonic
        assert stack_operand.sub("[esp+STACK]", before.op_str) == stack_operand.sub("[esp+STACK]", after.op_str)
        if before.bytes != after.bytes:
            assert before.op_str != after.op_str
            changed_instructions.append({"offset": before.address, "before": before.op_str, "current": after.op_str})
    frames = fixtures.cases()
    encoded = (json.dumps(frames, indent=2) + "\n").encode()
    (out / "frames.json").write_bytes(encoded)
    stacks = {name: {} for name in ("native", *programs)}
    rows = []
    for index, case in enumerate(frames):
        native, stack, _ = observe.run(current, True, case["frame"])
        merge_stack(stacks["native"], stack)
        call_digest = sha(json.dumps(native["calls"]).encode())
        if "prior_call_trace_sha256" in case:
            assert call_digest == case["prior_call_trace_sha256"], case["label"]
        if index < 251:
            assert native == observe.parent.run(current, True, case["frame"])
        for name, program in programs.items():
            candidate, stack, _ = observe.run(program, False, case["frame"])
            merge_stack(stacks[name], stack)
            for key in CHECKED:
                if native[key] != candidate[key]:
                    (out / "failure.json").write_text(json.dumps({"case": case, "program": name, "field": key, "native": native, "candidate": candidate}, indent=2) + "\n")
                    raise AssertionError((case["label"], name, key))
            if index < 251:
                assert candidate == observe.parent.run(program, False, case["frame"])
        rows.append({
            "label": case["label"], "call_trace_sha256": call_digest,
            "observation_sha256": sha(json.dumps({key: native[key] for key in CHECKED}).encode()),
            "calls": len(native["calls"]), "native_instructions": native["coverage"],
        })
    maps = {name: stack_map(p, stacks["native"], stacks[name], out / (name + ".cod")) for name, p in programs.items()}
    accesses = {
        name: {a["native_offset"]: a for row in mapping["locals"] for a in row["accesses"]}
        for name, mapping in maps.items()
    }
    assert accesses["before"].keys() == accesses["current"].keys()
    changes = []
    for offset, before in accesses["before"].items():
        after = accesses["current"][offset]
        assert before["native_entry_slot"] == after["native_entry_slot"]
        if before["candidate_entry_slot"] != after["candidate_entry_slot"]:
            changes.append({
                "native_offset": offset, "native_entry_slot": before["native_entry_slot"],
                "before": before["candidate_entry_slot"], "current": after["candidate_entry_slot"],
            })
    result = {
        "cases": len(frames), "frames_sha256": sha(encoded),
        "native_image_sha256": sha(match.default_image_path().read_bytes()),
        "native_body_sha256": sha(current.image.function_bytes(current.native_start, current.native_end)),
        "source_hashes": {name: sha((HERE / name).read_bytes()) for name in ("verify.py", "observe.py", "fixtures.py", "prior-frames.json")},
        "parent_runner_sha256": sha(Path(observe.parent.__file__).read_bytes()),
        "parent_loader_sha256": sha(observe.parent.ENGINE.read_bytes()),
        "programs": {name: metrics(p) for name, p in programs.items()},
        "before_current_changes_confined_to_esp_displacements": True,
        "changed_candidate_instructions": changed_instructions,
        "observed_and_plain_trace_equal_controls": 251 * 3,
        "x87_control_and_empty_stack_checks": len(frames) * 3,
        "checked_fields": CHECKED, "failing_cases": 0,
        "traces": rows, "stack_maps": maps, "changed_stack_accesses": changes,
        "restored_stack_accesses": sum(c["before"] != c["native_entry_slot"] == c["current"] for c in changes),
        "displaced_stack_accesses": sum(c["before"] == c["native_entry_slot"] != c["current"] for c in changes),
    }
    assert result["programs"]["current"]["ratio"] > result["programs"]["before"]["ratio"]
    assert result["programs"]["current"]["reference_problems"] == 0
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("cases", "failing_cases", "restored_stack_accesses", "displaced_stack_accesses")}))


if __name__ == "__main__":
    main()
