"""Check muzzle vector ownership against native calls and actual stack homes."""

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
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
observe, fixtures = previous.observe, previous.fixtures
match, sha = previous.match, previous.sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--source", type=Path, help="candidate source; defaults to the canonical scratch")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert observe.parent.unicorn.__version__ == "2.1.4"
    assert sha(match.default_image_path().read_bytes()) == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/player_render_overlays")
    before = (HERE / "before.cpp").read_bytes()
    assert sha(before) == "df048c95f7ba8cd30ab5b8ac3a4a9ad1ab46b658eea1ff7b6a6e3b1ae24fef2b"
    sources = {"before": before, "current": (args.source or config.directory / config.source).read_bytes()}
    programs = {}
    for name, source in sources.items():
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_bytes(source)
        programs[name] = observe.Program(replace(config, directory=directory))
    current = programs["current"]
    assert sha(sources["current"]) == "93a5f988ea28855eb588ce1fa6c6b687ee70c8d8b939b0ac70e592c7bcc98e98"
    result = current.result
    recovered_blocks = []
    for start, end in ((0xD31, 0xE71), (0xE8E, 0xF91)):
        sequences = {}
        for name, lines, disassembly in (
            ("native", result.target_lines, result.target_disassembly),
            ("current", result.candidate_lines, result.candidate_disassembly),
        ):
            sequences[name] = [(row.offset, row.size, line) for line, row in zip(lines, disassembly, strict=True)
                               if start <= row.offset < end]
        assert sequences["native"] == sequences["current"]
        assert sequences["native"][0][0] == start
        last = sequences["native"][-1]
        assert last[0] + last[1] == end
        recovered_blocks.append({"start": start, "end": end, "instructions": sequences["native"]})
    (out / "native-current.diff").write_text("\n".join(result.diff_lines()) + "\n")
    frames = fixtures.cases()
    encoded_frames = (json.dumps(frames, indent=2) + "\n").encode()
    assert sha(encoded_frames) == "16931caedaf6b66cf21ecdb7bde01806a85e222d20ba7af5ae9395362055cb83"
    stacks = {name: {} for name in ("native", *programs)}
    traces = []
    for index, case in enumerate(frames):
        native, stack, _ = observe.run(current, True, case["frame"])
        previous.merge_stack(stacks["native"], stack)
        call_hash = sha(json.dumps(native["calls"]).encode())
        if "prior_call_trace_sha256" in case:
            assert call_hash == case["prior_call_trace_sha256"], case["label"]
        if index < 251:
            assert native == observe.parent.run(current, True, case["frame"])
        for name, program in programs.items():
            candidate, stack, _ = observe.run(program, False, case["frame"])
            previous.merge_stack(stacks[name], stack)
            for key in previous.CHECKED:
                assert native[key] == candidate[key], (case["label"], name, key)
            if index < 251:
                assert candidate == observe.parent.run(program, False, case["frame"])
        traces.append({"label": case["label"], "call_trace_sha256": call_hash,
                       "observation_sha256": sha(json.dumps({key: native[key] for key in previous.CHECKED}).encode())})
        if (index + 1) % 200 == 0:
            print(f"Verified {index + 1}/{len(frames)} native/before/current cases", flush=True)
    maps = {name: previous.stack_map(p, stacks["native"], stacks[name], out / (name + ".cod")) for name, p in programs.items()}
    accesses = {name: {a["native_offset"]: a for row in value["locals"] for a in row["accesses"]} for name, value in maps.items()}
    assert accesses["before"].keys() <= accesses["current"].keys()
    changes = []
    for offset, before_access in accesses["before"].items():
        after = accesses["current"][offset]
        assert before_access["native_entry_slot"] == after["native_entry_slot"]
        if before_access["candidate_entry_slot"] != after["candidate_entry_slot"]:
            changes.append({"native_offset": offset, "native_entry_slot": before_access["native_entry_slot"],
                            "before": before_access["candidate_entry_slot"], "current": after["candidate_entry_slot"]})
    assert len(changes) == 22
    assert all(row["before"] != row["native_entry_slot"] == row["current"] for row in changes)
    added = [accesses["current"][offset] for offset in sorted(accesses["current"].keys() - accesses["before"].keys())]
    assert [row["native_offset"] for row in added] == [0xE9A, 0xEB6, 0xEBA]
    assert all(row["candidate_entry_slot"] == row["native_entry_slot"] for row in added)
    assert maps["before"]["mismatches"] == 26 and maps["current"]["mismatches"] == 4
    remaining = [a for a in accesses["current"].values() if a["candidate_entry_slot"] != a["native_entry_slot"]]
    assert sorted(a["native_offset"] for a in remaining) == [2165, 2175, 2522, 2532]
    assert all(a["native_entry_slot"] == -36 and a["candidate_entry_slot"] == -40 for a in remaining)
    result = {
        "cases": len(frames), "failing_cases": 0, "frames_sha256": sha(encoded_frames),
        "script_sha256": sha(Path(__file__).read_bytes()),
        "parent_files": {name: sha((PARENT / name).read_bytes()) for name in ("verify.py", "observe.py", "fixtures.py", "prior-frames.json")},
        "parent_runner_sha256": sha(Path(observe.parent.__file__).read_bytes()),
        "parent_loader_sha256": sha(observe.parent.ENGINE.read_bytes()),
        "native_image_sha256": sha(match.default_image_path().read_bytes()),
        "native_body_sha256": sha(current.image.function_bytes(current.native_start, current.native_end)),
        "programs": {name: previous.metrics(p) for name, p in programs.items()},
        "recovered_normalized_blocks": recovered_blocks, "added_paired_stack_accesses": added,
        "stack_maps": maps, "changed_stack_accesses": changes, "restored_stack_accesses": 22, "displaced_stack_accesses": 0,
        "checked_fields": previous.CHECKED, "observed_and_plain_trace_equal_controls": 251 * 3,
        "x87_control_and_empty_stack_checks": len(frames) * 3, "traces": traces,
    }
    assert result["programs"]["current"]["ratio"] > result["programs"]["before"]["ratio"]
    assert result["programs"]["current"]["references_ok"] == 333
    assert result["programs"]["current"]["reference_problems"] == 0
    assert result["programs"]["current"]["candidate_instructions"] == 1149
    assert result["programs"]["current"]["target_instructions"] == 1148
    assert not result["programs"]["current"]["exact"] and not result["programs"]["current"]["body_byte_exact"]
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("cases", "failing_cases", "restored_stack_accesses", "displaced_stack_accesses")}))


if __name__ == "__main__":
    main()
