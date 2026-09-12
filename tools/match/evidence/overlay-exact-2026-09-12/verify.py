"""Verify the exact overlay recovery against native calls and stack homes."""

import argparse
import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent / "overlay-size-ownership-2026-09-11"
sys.path.insert(0, str(PARENT))
spec = importlib.util.spec_from_file_location("size_proof", PARENT / "verify.py")
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)
match, sha = parent.match, parent.sha
BEFORE_SHA = "322be4d21391ba19a4ad893e033f2d08238e6393acdafaac2e96b64dc8632172"
CURRENT_SHA = "8a403a6a4c6c7bf63cc276950e407adb8bf2d1f7cac6d56d228950dde6941181"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert parent.observe.parent.unicorn.__version__ == "2.1.4"
    assert sha(match.default_image_path().read_bytes()) == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/player_render_overlays")
    sources = {"before": (HERE / "before.cpp").read_bytes(), "current": (config.directory / config.source).read_bytes()}
    assert sha(sources["before"]) == BEFORE_SHA
    assert sha(sources["current"]) == CURRENT_SHA
    programs = {}
    for name, source in sources.items():
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_bytes(source)
        programs[name] = parent.observe.Program(replace(config, directory=directory))
    current = programs["current"]
    frames = parent.fixtures.cases()
    frames_sha = sha((json.dumps(frames, indent=2) + "\n").encode())
    assert frames_sha == "16931caedaf6b66cf21ecdb7bde01806a85e222d20ba7af5ae9395362055cb83"
    stacks = {name: {} for name in ("native", *programs)}
    traces = []
    for index, case in enumerate(frames):
        native, stack, _ = parent.observe.run(current, True, case["frame"])
        parent.merge_stack(stacks["native"], stack)
        call_hash = sha(json.dumps(native["calls"]).encode())
        if "prior_call_trace_sha256" in case:
            assert call_hash == case["prior_call_trace_sha256"], case["label"]
        for name, program in programs.items():
            candidate, stack, _ = parent.observe.run(program, False, case["frame"])
            parent.merge_stack(stacks[name], stack)
            for key in parent.CHECKED:
                assert native[key] == candidate[key], (case["label"], name, key)
        traces.append({"label": case["label"], "call_trace_sha256": call_hash,
                       "observation_sha256": sha(json.dumps({key: native[key] for key in parent.CHECKED}).encode())})
        if (index + 1) % 200 == 0:
            print(f"Verified {index + 1}/{len(frames)} native/before/current cases", flush=True)
    maps = {name: parent.stack_map(p, stacks["native"], stacks[name], out / (name + ".cod"))
            for name, p in programs.items()}
    accesses = {name: {a["native_offset"]: a for row in value["locals"] for a in row["accesses"]}
                for name, value in maps.items()}
    assert accesses["before"].keys() == accesses["current"].keys()
    assert len(accesses["current"]) == 202
    assert maps["before"]["mismatches"] == 0 and maps["current"]["mismatches"] == 0
    changes = []
    for offset, before in accesses["before"].items():
        after = accesses["current"][offset]
        assert before["native_entry_slot"] == after["native_entry_slot"] == after["candidate_entry_slot"]
        if before["candidate_entry_slot"] != after["candidate_entry_slot"]:
            changes.append({"native_offset": offset, "native_entry_slot": after["native_entry_slot"],
                            "before": before["candidate_entry_slot"], "current": after["candidate_entry_slot"]})
    assert not changes
    metrics = {name: parent.metrics(p) for name, p in programs.items()}
    assert metrics["current"]["candidate_instructions"] == metrics["current"]["target_instructions"] == 1148
    assert metrics["current"]["references_ok"] == 340 and metrics["current"]["reference_problems"] == 0
    assert metrics["current"]["exact"] and metrics["current"]["body_byte_exact"]
    result = {
        "cases": len(frames), "failing_cases": 0, "frames_sha256": frames_sha,
        "script_sha256": sha(Path(__file__).read_bytes()),
        "parent_files": {name: sha((PARENT / name).read_bytes()) for name in ("verify.py", "observe.py", "fixtures.py", "prior-frames.json")},
        "parent_runner_sha256": sha(Path(parent.observe.parent.__file__).read_bytes()),
        "parent_loader_sha256": sha(parent.observe.parent.ENGINE.read_bytes()),
        "native_image_sha256": sha(match.default_image_path().read_bytes()),
        "native_body_sha256": sha(current.image.function_bytes(current.native_start, current.native_end)),
        "programs": metrics, "stack_maps": maps, "changed_stack_accesses": changes,
        "restored_stack_accesses": 0, "displaced_stack_accesses": 0,
        "checked_fields": parent.CHECKED, "x87_control_and_empty_stack_checks": len(frames) * 3, "traces": traces,
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    (out / "native-current.diff").write_text("\n".join(current.result.diff_lines()) + "\n")
    print(f"Verified {len(frames)} cases and all 202 paired stack homes")


if __name__ == "__main__":
    main()
