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
call = """                creature_spawn_template(
                    *template_id,
                    (const vec2f_t *)&pos,
                    entry->heading);"""
assert call in s
cases = [
    (
        "id-postinc",
        "int *template_id = &entry->template_id;",
        "float heading = ((float *)template_id)[-1];\n                int id = *template_id++;",
        "--template_id;",
    ),
    (
        "heading-predec",
        "int *template_id = &entry->template_id;",
        "float heading = *(float *)--template_id;\n                int id = *++template_id;",
        "",
    ),
    (
        "heading-postinc",
        "int *template_id = (int *)&entry->heading;",
        "float heading = *(float *)template_id++;\n                int id = *template_id;",
        "--template_id;",
    ),
    (
        "pair-postinc",
        "int *template_id = (int *)&entry->heading;",
        "float heading = *(float *)template_id++;\n                int id = *template_id++;",
        "template_id -= 2;",
    ),
    (
        "pair-reset",
        "int *template_id = (int *)&entry->heading;",
        "float heading = *(float *)template_id++;\n                int id = *template_id++;",
        "template_id = (int *)&entry->heading;",
    ),
]
controls = []
for name, decl, reads, restore in cases:
    for where in ["before-pos", "after-pos"]:
        src = s.replace("int *template_id = &entry->template_id;", decl)
        newcall = """                creature_spawn_template(id, (const vec2f_t *)&pos, heading);"""
        src = src.replace(
            call,
            ("                " + reads + "\n" if where == "after-pos" else "")
            + newcall
            + "\n                "
            + restore,
        )
        if where == "before-pos":
            src = src.replace(
                "                quest_timeline_vec2_t pos(",
                "                " + reads + "\n                quest_timeline_vec2_t pos(",
            )
        controls.append((name + "-" + where, src))
# Inline byte-stream readers, sequenced explicitly before the spawn call.
helpers = """static __inline float read_heading(const char *&p) { float v=*(const float *)p; p+=4; return v; }
static __inline int read_id(const char *&p) { int v=*(const int *)p; p+=4; return v; }
"""
for restore in ["template_id -= 8;", "template_id = (const char *)&entry->heading;"]:
    src = s.replace(
        "int *template_id = &entry->template_id;",
        "const char *template_id = (const char *)&entry->heading;",
    ).replace('extern "C" int frame_dt_ms;', helpers + 'extern "C" int frame_dt_ms;')
    src = src.replace(
        call,
        "                float heading=read_heading(template_id);\n                int id=read_id(template_id);\n                creature_spawn_template(id, (const vec2f_t *)&pos, heading);\n                "
        + restore,
    )
    controls.append(("readers-" + ("rewind" if "-=" in restore else "reset"), src))
rows = []
for name, src in controls:
    row, _, _ = probes.build(c, out, name, src)
    rows.append(row)
    print(json.dumps(row), flush=True)
(out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
