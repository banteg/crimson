"""Separate creature address units from pointer retention; diagnostic only."""

import argparse
import importlib.util
import json
import shutil
import struct
from collections import Counter
from pathlib import Path

from crimson import match
from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

HERE = Path(__file__).resolve().parent
SOURCE_SHA = "b27f450cd219a514e9083ddfb87842a3a960130f6d5343b851ae6f7835b9ddae"


def summarize_trace(snapshots):
    rows = []
    for snapshot in snapshots:
        nodes = snapshot["nodes"]
        rows.append({
            "phase": snapshot["phase"],
            "target_rva": hex(snapshot["target_rva"]),
            "offset_line_operations": [hex(n["op"]) for n in nodes if n["line"] == 20],
            "health_line_operations": [hex(n["op"]) for n in nodes if n["line"] == 27],
        })
    # Infer the shared symbol independently inside each event, never by arena address.
    for phase in (1, 2):
        nodes = snapshots[phase]["nodes"]
        definitions = [n for n in nodes if n["line"] == 20 and n["op"] == 0x16F]
        assert len(definitions) == 1
        definition = definitions[0]
        assert [o["kind"] for o in definition["src"]] == [2, 7]
        assert definition["src"][1]["raw"][6] == 152
        symbol = definition["dst"][0]["raw"][5]
        uses = [n for n in nodes if any(o["raw"][5] == symbol for o in n["src"])]
        assert len(uses) == 105
        assert all(n["op"] == 0x16D and [o["kind"] for o in n["src"]] == [2, 3] for n in uses)
        rows[phase]["shared_offset_address_uses"] = len(uses)
    assert 0x2A not in [n["op"] for n in snapshots[3]["nodes"] if n["line"] == 20]
    assert 0x2A in [n["op"] for n in snapshots[4]["nodes"] if n["line"] == 20]
    assert rows[9]["health_line_operations"] == ["0x12", "0x1"]
    assert rows[10]["health_line_operations"] == []
    return rows


def controlled_replay(baseline, out, config, rescale, retain):
    out.mkdir()
    shutil.copyfile(baseline / "observed/replay_settings.h", out / "replay_settings.h")
    source = (baseline / "observed/observer.c").read_text().replace(
        "static HANDLE trace_file;",
        f"#define DO_RESCALE {int(rescale)}\n#define KEEP_HEALTH {int(retain)}\nstatic HANDLE trace_file;\n"
        + (HERE / "rescale.c.in").read_text() + (HERE / "retain.c.in").read_text(),
    )
    source = source.replace(
        "    node = first;",
        "    if(phase==4)rescale_offset(first);\n    if(phase==9)retain_health(first);\n    node = first;",
    ).replace(
        "    CloseHandle(trace_file);",
        "    if(intervention_count!=1 || health_intervention_count!=1)ExitProcess(78);\n    CloseHandle(trace_file);",
    )
    (out / "observer.c").write_text(source)
    with c2.compiler_environment():
        replay.compile_driver(out, "observer.c", "observer.obj")
        replay.link(out, "observer.exe", "observer.obj")
        replay.run([replay.WIBO, "observer.exe"], out)
    counts = struct.unpack("<3I", (out / "counts.bin").read_bytes())
    assert counts == (1, 105, 105)
    profile = c2.load_profile()
    profile["hooks"] = profile["hooks"][:12]
    snapshots = c2.decode_trace((out / "phases.bin").read_bytes(), profile)
    health = {s["phase"]: [hex(n["op"]) for n in s["nodes"] if n["line"] == 27] for s in snapshots}
    assert health[10] == (["0x12"] if retain else [])
    assert health[11] == []
    result = match.run_match(obj_path=out / "replay.obj", function=config.function, symbol_name=config.symbol,
                             reference_aliases=config.reference_aliases)
    assert result.candidate_lines[13:15] == (
        "lea eax, dword [esi+esi*8]", "lea esi, dword [esi+eax*2]",
    )
    assert result.candidate_lines[15] == ("mov al, byte [esi*8+ADDR]" if rescale else "shl esi, 0x3")
    assert result.candidate_lines[0] == ("sub esp, 0x70" if rescale else "sub esp, 0x7c")
    (out / "candidate.txt").write_text("\n".join(result.candidate_lines) + "\n")
    return {
        "rescale_offset": rescale, "retain_health_one_pass": retain, "match_credit": False,
        "counts": {"definitions": counts[0], "uses": counts[1], "address_operands": counts[2]},
        "metrics": replay.function_metrics(config, out / "replay.obj"),
        "health_operations_after_substitution": health[10], "health_operations_after_allocation": health[11],
        "frame_bytes": 112 if rescale else 124,
        "normalized_coff_sha256": replay.sha(replay.normalized_coff(out / "replay.obj")),
        "observer_sha256": replay.sha(source.encode()),
    }


def behavior(config, out):
    path = HERE.parent / "creature-retarget-distance-2026-09-13/verify.py"
    spec = importlib.util.spec_from_file_location("creature_offset_fixtures", path)
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    assert fixtures.engine.unicorn.__version__ == "2.1.4"
    programs = []
    compile_scratch = match.compile_scratch
    try:
        for name in ("baseline", "scaled"):
            match.compile_scratch = lambda *args, object_path=out / name / "replay.obj", **kwargs: object_path
            programs.append(fixtures.engine.Comparison(config))
    finally:
        match.compile_scratch = compile_scratch
    cases = (fixtures.corpse.fixtures.scenarios() + list(fixtures.boundary_cases())
             + list(fixtures.corpse.interaction.boundary_cases()) + list(fixtures.corpse.tiny_cases()))
    assert len(cases) == 3480
    differences, rows = [], []
    totals = Counter()
    for index, case in enumerate(cases):
        native = programs[0].run(True, case)
        baseline = programs[0].run(False, case)
        scaled = programs[1].run(False, case)
        assert all(native[k] == baseline[k] for k in fixtures.legacy.KEYS), case["name"]
        changed = [k for k in fixtures.legacy.KEYS if baseline[k] != scaled[k]]
        totals.update(changed)
        if changed:
            differences.append({"case": case, "differences": {
                k: fixtures.legacy.first_difference(baseline[k], scaled[k]) for k in changed}})
        rows.append({"name": case["name"], "native_and_baseline": fixtures.legacy.observation(baseline),
                     "scaled": fixtures.legacy.observation(scaled)})
        if index % 400 == 0:
            print(f"Behavior {index}/{len(cases)}", flush=True)
    assert dict(totals) == {"writes": 2}
    assert {d["case"]["name"] for d in differences} == {"animation-wrap-4-pc37f", "animation-wrap-4-pc07f"}
    (out / "behavior.json").write_text(json.dumps(rows, indent=2) + "\n")
    return {"cases": len(cases), "native_baseline_differences": 0, "changed_observations": dict(totals),
            "witnesses": differences, "rows_sha256": replay.sha((out / "behavior.json").read_bytes()),
            "scope": "Finite native x86 observations with existing callback models; not whole-game equivalence."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/creature_update_all")
    assert replay.sha((config.directory / config.source).read_bytes()) == SOURCE_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    manifest = c2.trace(config.directory, out / "preserving", passes_only=True)
    stages = summarize_trace(c2.read_verified(out / "preserving"))
    rows = {}
    for name, rescale, retain in (("baseline", False, False), ("scaled", True, False),
                                 ("health", False, True), ("scaled-health", True, True)):
        rows[name] = controlled_replay(out / "preserving", out / name, config, rescale, retain)
    assert rows["baseline"]["normalized_coff_sha256"] == manifest["normalized_coff_sha256"]
    assert rows["baseline"]["normalized_coff_sha256"] == rows["health"]["normalized_coff_sha256"]
    assert rows["scaled"]["normalized_coff_sha256"] == rows["scaled-health"]["normalized_coff_sha256"]
    print("Four replay controls verified; health retention changes no final COFF", flush=True)
    result = {"schema_version": 1, "kind": "creature-offset-unit-causality", "match_credit": False,
              "canonical_source_sha256": SOURCE_SHA, "canonical_source_modified": False,
              "c2_sha256": c2.load_profile()["c2_sha256"],
              "image_sha256": replay.sha(match.DEFAULT_IMAGE_PATH.read_bytes()),
              "preserving_manifest_sha256": replay.sha((out / "preserving/manifest.json").read_bytes()),
              "stages": stages, "controls": rows, "behavior": behavior(config, out),
              "harness_sha256": {name: replay.sha((HERE / name).read_bytes())
                                 for name in ("verify.py", "rescale.c.in", "retain.c.in")}}
    assert replay.sha((config.directory / config.source).read_bytes()) == SOURCE_SHA
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Completed diagnostic; no source or exact-match credit", flush=True)


if __name__ == "__main__":
    main()
