"""Bounded stock-compiler controls; canonical source is unchanged."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vc6-timeline-consumers-2026-09-11"))
import probes

from crimson import match

c = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
s = (c.directory / c.source).read_text()
assert probes.SOURCE_SHA == probes.hashlib.sha256(s.encode()).hexdigest()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
rows = []
call = """                creature_spawn_template(
                    *template_id,
                    (const vec2f_t *)&pos,
                    entry->heading);"""
for name, setup, idexpr, headingexpr in [
    ("heading-ref", "float &heading = *(float *)--template_id; ++template_id;", "*template_id", "heading"),
    ("heading-ptr", "float *heading = (float *)--template_id; ++template_id;", "*template_id", "*heading"),
    ("id-ref", "int &id = *template_id++; --template_id;", "id", "((float *)template_id)[-1]"),
    ("id-ptr", "int *id = template_id++; --template_id;", "*id", "((float *)template_id)[-1]"),
]:
    for site in ["outside", "inside"]:
        src = s.replace(
            call,
            "                creature_spawn_template(" + idexpr + ", (const vec2f_t *)&pos, " + headingexpr + ");",
        )
        if site == "outside":
            src = src.replace("            int spread;", "            " + setup + "\n            int spread;")
        else:
            src = src.replace(
                "                quest_timeline_vec2_t pos(",
                "                " + setup + "\n                quest_timeline_vec2_t pos(",
            )
        row, _, _ = probes.build(c, out, name + "-" + site, src)
        rows.append(row)
        print(json.dumps(row), flush=True)
(out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
