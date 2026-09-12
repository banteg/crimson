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
for flag in ["/Zd", "/Z7", "/Zi", "/ZI", "/GX", "/Gi"]:
    for heading in ["entry", "relative"]:
        src = s if heading == "entry" else s.replace("entry->heading", "((float *)template_id)[-1]")
        name = flag[1:] + "-" + heading
        try:
            row, _, _ = probes.build(c, out, name, src, extra_flags=" " + flag)
            rows.append(row)
            print(json.dumps(row), flush=True)
        except RuntimeError as e:
            rows.append({"label": name, "error": str(e)})
            print(name, str(e)[:700], flush=True)
(out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
