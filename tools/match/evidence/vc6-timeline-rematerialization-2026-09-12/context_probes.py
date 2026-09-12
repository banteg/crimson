"""Bounded stock-compiler controls; canonical source is unchanged."""

import argparse
import json
import re
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
controls = []
for name in ["creature_spawn_template", "tutorial_timeline_update"]:
    p = match.DEFAULT_MATCH_ROOT / "scratches" / name / "scratch.cpp"
    text = p.read_text()
    cleanup = "\n" + "".join("#undef " + m + "\n" for m in re.findall(r"^#define\s+(\w+)", text, re.MULTILINE))
    for placement in ["before", "after"]:
        source = text + cleanup + s if placement == "before" else s + text
        controls.append((name + "-" + placement, source))
for decl in ["register int *template_id", "int *const template_id"]:
    controls.append(
        (("register" if decl.startswith("register") else "const") + "-ptr", s.replace("int *template_id", decl)),
    )
rows = []
for name, src in controls:
    try:
        row, _, _ = probes.build(c, out, name, src)
        rows.append(row)
        print(json.dumps(row), flush=True)
    except RuntimeError as e:
        rows.append({"label": name, "error": str(e)})
        print(name, str(e)[:1500], flush=True)
(out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
