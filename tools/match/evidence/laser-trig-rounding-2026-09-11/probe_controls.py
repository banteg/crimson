"""Compile seven local trig-store controls and replay the discovery witnesses."""

import argparse
import json
from dataclasses import replace
from pathlib import Path

import execute as p
from verify import BEFORE_SHA, HERE, metrics

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
config = p.match.load_scratch_config(p.match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
source = (HERE / "before.cpp").read_text()
assert p.sha(source.encode()) == BEFORE_SHA
receipt = json.loads((HERE / "results.json").read_text())
fixture_path = HERE / receipt["fixtures"]["file"]
assert p.sha(fixture_path.read_bytes()) == receipt["fixtures"]["sha256"]
rows = [json.loads(line) for line in fixture_path.read_text().splitlines()]
selected = [r for r in rows if r["case"]["group"] == "discovery" and (not r["before_agrees"] or r["index"] < 64)]
assert len(selected) == 70
start = """            projectile_render_vec2_t start_pos =
                player_pos
                + projectile_render_vec2_t(
                      (float)cos(start_heading), (float)sin(start_heading))
                    * 15.0f;"""
width = """            projectile_render_vec2_t half_width =
                projectile_render_vec2_t(
                    (float)cos(player->aim_heading),
                    (float)sin(player->aim_heading))
                * 1.1f;"""
assert start in source and width in source
starts = {
    "component": """            projectile_render_vec2_t start_pos = player_pos;
            start_pos += projectile_render_vec2_t(
                (float)cos(start_heading) * 15.0f,
                (float)sin(start_heading) * 15.0f);""",
    "sum": """            projectile_render_vec2_t start_pos = player_pos
                + projectile_render_vec2_t(
                    (float)cos(start_heading) * 15.0f,
                    (float)sin(start_heading) * 15.0f);""",
    "direct": """            projectile_render_vec2_t start_pos(
                player_pos.x + (float)cos(start_heading) * 15.0f,
                player_pos.y + (float)sin(start_heading) * 15.0f);""",
}
newwidth = """            projectile_render_vec2_t half_width(
                (float)cos(player->aim_heading) * 1.1f,
                (float)sin(player->aim_heading) * 1.1f);"""
results = []
for name, start_text in [("before", start), *starts.items()]:
    for change_width in (False, True):
        if name == "before" and not change_width:
            continue
        label = f"{name}-width{int(change_width)}"
        directory = out / label
        directory.mkdir(parents=True, exist_ok=True)
        text = source.replace(start, start_text).replace(width, newwidth if change_width else width)
        (directory / config.source).write_text(text)
        program = p.Program(replace(config, directory=directory))
        failed = []
        for row in selected:
            got = p.run(program, False, row["case"])
            assert got["pools"] == row["pools"]
            if p.sha(json.dumps(got["calls"]).encode()) != row["native_trace_sha256"]:
                failed.append(row["index"])
        record = {
            "name": label,
            "failures": failed,
            "metrics": metrics(program),
            "source_sha256": p.sha(text.encode()),
            "body_sha256": p.sha(program.body.data),
        }
        results.append(record)
        print(record, flush=True)
record = {
    "schema_version": 1,
    "kind": "bounded-laser-trig-store-source-controls",
    "before_source_sha256": BEFORE_SHA,
    "verifier_sha256": p.sha(Path(__file__).read_bytes()),
    "executor_sha256": p.sha((HERE / "execute.py").read_bytes()),
    "fixture_sha256": p.sha(fixture_path.read_bytes()),
    "selected_indices": [r["index"] for r in selected],
    "controls": results,
    "scope": "Seven concrete source controls and 70 recorded discovery cases; no source-shape ceiling claim",
}
(out / "source-controls.json").write_text(json.dumps(record, indent=2) + "\n")
