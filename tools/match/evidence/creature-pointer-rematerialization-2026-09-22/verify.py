"""Locate and control health-pointer reconstruction without source-match credit."""

import argparse
import json
import shutil
import struct
from dataclasses import replace
from pathlib import Path

from crimson import match
from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

HERE = Path(__file__).resolve().parent
SOURCE_SHA = "b27f450cd219a514e9083ddfb87842a3a960130f6d5343b851ae6f7835b9ddae"
SITES = (0x5273A, 0x6A6B9, 0x52659, 0x8E4F7, 0x333AD, 0x33507, 0x3352D)
MODES = {
    "control": (0, 0, 0),
    "early": (1, 0, 0),
    "early-allocation": (1, 1, 0),
    "early-allocation-spill": (1, 3, 0),
    "original-definition": (1, 7, 0),
    "health-value": (1, 7, 1),
    "health-home": (1, 15, 1),
}


def profile():
    stock = c2.load_profile()
    return dict(stock, hooks=stock["hooks"][:12] + [
        {"site": 0x2FE4D, "target": 0x32216, "return": True},
        *({"site": site, "target": 0x527B2 if i < 3 else 0x21F97, "return": True}
          for i, site in enumerate(SITES)),
    ])


def observer(original, hooks, mode):
    early, mask, owner = MODES[mode]
    source = original(hooks).replace(
        "static HANDLE trace_file;",
        f"#define KEEP_EARLY {early}\n#define REJECT_MASK {mask}\n#define FOLLOW_OWNER {owner}\n"
        "static HANDLE trace_file;\n" + (HERE / "watch.c.in").read_text(),
    )
    source = source.replace("    node = first;", "    if(!watch(phase,registers,first))return;\n    node = first;")
    source = source.replace(
        "    trace_file = CreateFileA(",
        '    decisions_file=CreateFileA("decisions.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
        "    if(decisions_file==INVALID_HANDLE_VALUE)ExitProcess(79);\n    trace_file = CreateFileA(",
    )
    return source.replace("    CloseHandle(trace_file);", "    finish_watch();\n    CloseHandle(trace_file);")


def inspect(directory, config, hooks):
    raw = (directory / "decisions.bin").read_bytes()
    assert len(raw) >= 96 and (len(raw) - 96) % 32 == 0
    counts = struct.unpack_from("<24I", raw, len(raw) - 96)
    events = list(struct.iter_unpack("<8I", raw[:-96]))
    assert len(events) % 2 == 0
    decisions = []
    for before, after in zip(events[::2], events[1::2], strict=True):
        assert after[0] == before[0] + 100
        decisions.append({"callsite": hex(SITES[before[0] - 13]), "definition": before[1],
                          "owner": before[2], "temporary": before[3], "initial_temporary": before[4],
                          "line": before[5], "original_return": after[1], "rejected": bool(after[2])})
    snapshots = c2.decode_trace((directory / "phases.bin").read_bytes(), hooks)
    assert len(snapshots) == 14
    health = {s["phase"]: [n for n in s["nodes"] if n["line"] == 27] for s in snapshots}
    result = match.run_match(obj_path=directory / "replay.obj", function=config.function,
                             symbol_name=config.symbol, reference_aliases=config.reference_aliases)
    (directory / "candidate.txt").write_text("\n".join(result.candidate_lines) + "\n")
    return {
        "counts": {"early": counts[0], "allocation_calls": counts[1], "seen": list(counts[3:10]),
                   "positive": list(counts[10:17]), "rejected": list(counts[17:24])},
        "decisions": decisions,
        "health_operations": {str(phase): [hex(n["op"]) for n in health[phase]] for phase in (9, 10, 12, 112, 11)},
        "metrics": replay.function_metrics(config, directory / "replay.obj"),
        "frame_instruction": result.candidate_lines[0],
        "opening": list(result.candidate_lines[34:43]),
        "normalized_coff_sha256": replay.sha(replay.normalized_coff(directory / "replay.obj")),
        "observer_sha256": replay.sha((directory / "observer.c").read_bytes()),
        "trace_sha256": replay.sha((directory / "phases.bin").read_bytes()),
        "decision_sha256": replay.sha(raw),
    }


def source_controls(config, out, baseline):
    source = (config.directory / config.source).read_text()
    base = source.replace("    float *health;\n", "")
    variants = {
        "field-reference": base.replace("health = &creature_pool[creature_index].health;",
                                        "float &health = creature_pool[creature_index].health;").replace("*health", "health"),
        "bound-pointer-reference": base.replace("health = &creature_pool[creature_index].health;",
                                                "float *const &health = &creature_pool[creature_index].health;"),
    }
    rows = {}
    # Compare emitted function bytes AND its complete COFF relocation descriptors.
    def body(path):
        obj = match.parse_coff_object(path.read_bytes())
        value = match.extract_object_function(obj, config.symbol)
        return value
    expected = body(baseline)
    for name, text in variants.items():
        directory = out / name
        directory.mkdir()
        (directory / config.source).write_text(text)
        candidate = replace(config, directory=directory)
        object_path = match.compile_scratch(candidate, force=True)
        actual = body(object_path)
        assert actual.data == expected.data
        assert actual.relocation_references == expected.relocation_references
        rows[name] = {"source_sha256": replay.sha(text.encode()), "encoded_bytes_equal": True,
                      "relocations_equal": True, "body_sha256": replay.sha(actual.data)}
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/creature_update_all")
    assert replay.sha((config.directory / config.source).read_bytes()) == SOURCE_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    hooks = profile()
    original_loader, original_observer = c2.load_profile, c2.observer_source
    try:
        c2.load_profile = lambda: hooks
        c2.observer_source = lambda p: observer(original_observer, p, "control")
        manifest = c2.trace(config.directory, out / "preserving")
    finally:
        c2.load_profile, c2.observer_source = original_loader, original_observer
    rows = {"control": inspect(out / "preserving/observed", config, hooks)}
    for mode in list(MODES)[1:]:
        directory = out / mode
        directory.mkdir()
        shutil.copyfile(out / "preserving/observed/replay_settings.h", directory / "replay_settings.h")
        (directory / "observer.c").write_text(observer(original_observer, hooks, mode))
        with c2.compiler_environment():
            replay.compile_driver(directory, "observer.c", "observer.obj")
            replay.link(directory, "observer.exe", "observer.obj")
            replay.run([replay.WIBO, "observer.exe"], directory)
        rows[mode] = inspect(directory, config, hooks)
        print(mode, rows[mode]["counts"]["rejected"], rows[mode]["frame_instruction"], flush=True)
    stock = rows["control"]["normalized_coff_sha256"]
    assert stock == manifest["normalized_coff_sha256"]
    assert all(rows[name]["normalized_coff_sha256"] == stock for name in ("early", "early-allocation", "early-allocation-spill"))
    assert rows["early"]["health_operations"]["112"] == []
    assert rows["early-allocation"]["health_operations"]["112"] == ["0x12"]
    assert rows["original-definition"]["health_operations"]["11"] == ["0x12"]
    assert rows["health-home"]["health_operations"]["11"] == ["0x12", "0x1"]
    assert rows["health-home"]["frame_instruction"] == "sub esp, 0x80"
    assert sum(rows["original-definition"]["counts"]["rejected"]) == 3
    assert sum(rows["health-value"]["counts"]["rejected"]) == 7
    result = {"schema_version": 1, "kind": "creature-pointer-rematerialization", "match_credit": False,
              "canonical_source_sha256": SOURCE_SHA, "canonical_source_modified": False,
              "c2_sha256": hooks["c2_sha256"], "preserving_manifest_sha256": replay.sha((out / "preserving/manifest.json").read_bytes()),
              "controls": rows, "source_controls": source_controls(config, out, out / "preserving/observed/replay.obj"),
              "harness_sha256": {name: replay.sha((HERE / name).read_bytes()) for name in ("verify.py", "watch.c.in")}}
    assert replay.sha((config.directory / config.source).read_bytes()) == SOURCE_SHA
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified reconstruction routes, regional splitting, stored pointer, and two source controls", flush=True)


if __name__ == "__main__":
    main()
