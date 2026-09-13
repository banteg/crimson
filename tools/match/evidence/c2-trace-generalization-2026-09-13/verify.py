"""Exercise reusable C2 tracing on frozen C/C++ controls and a source variant."""

import argparse
import json
import shutil
from pathlib import Path

from crimson import match
from crimson import match_c2 as c2

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=False)
rows = {}
for label, function in (
    ("timeline", "quest_spawn_timeline_update"),
    ("repeat", "quest_spawn_timeline_update"),
    ("c-exact", "plaguebearer_spread_infection"),
    ("cpp-exact", "statistics_update_check_worker"),
):
    row = c2.trace(match.DEFAULT_MATCH_ROOT / "scratches" / function, out / label)
    rows[label] = row
    print(label, row["events"], "events; COFF preserved", flush=True)
multi = out / "multi-source"
shutil.copytree(match.DEFAULT_MATCH_ROOT / "scratches/plaguebearer_spread_infection", multi,
                ignore=shutil.ignore_patterns("build", "__pycache__"))
multi_source = multi / "scratch.c"
# Respect the source filename selected by the scratch configuration.
multi_source = multi / match.load_scratch_config(multi).source
multi_source.write_text(multi_source.read_text() + "\nint c2_trace_control(int value) { return value + 1; }\n")
rows["multi-function"] = c2.trace(multi, out / "multi-function")
assert len({e["function_ordinal"] for e in c2.read_verified(out / "multi-function")}) == 2
original = match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update"
variant = out / "variant-source"
shutil.copytree(original, variant, ignore=shutil.ignore_patterns("build", "__pycache__"))
source = (variant / "scratch.cpp").read_text()
assert source.count("entry->heading") == 1
(variant / "scratch.cpp").write_text(source.replace("entry->heading", "((float *)template_id)[-1]"))
rows["relative-heading"] = c2.trace(variant, out / "relative-heading")
a = c2.read_verified(out / "timeline")
b = c2.read_verified(out / "repeat")
repeat = c2.compare(a, b)
assert not repeat["differences"], repeat["first_shape_difference"]
changed = c2.compare(a, c2.read_verified(out / "relative-heading"))
assert changed["differences"]
assert rows["c-exact"]["metrics"]["body_byte_exact"]
assert rows["cpp-exact"]["metrics"]["body_byte_exact"]
# Wrong expected call target must be rejected before the observed backend runs.
profile = c2.load_profile()
profile["hooks"][0]["target"] += 1
bad = out / "bad-hook"
bad.mkdir()
shutil.copyfile(out / "timeline/replay/replay_settings.h", bad / "replay_settings.h")
(bad / "observer.c").write_text(c2.observer_source(profile))
with c2.compiler_environment():
    c2.replay.compile_driver(bad, "observer.c", "observer.obj")
    c2.replay.link(bad, "observer.exe", "observer.obj")
    rejected = c2.replay.run([c2.replay.WIBO, "observer.exe"], bad, check=False)
assert rejected.returncode == 95 and not (bad / "replay.obj").exists()
record = {
    "kind": "c2-generalization-validation",
    "runs": rows,
    "repeat_comparison": repeat,
    "variant_comparison": changed,
    "bad_hook_rejected": True,
    "functions_observed": {k: len({e["function_ordinal"] for e in c2.read_verified(out / k)}) for k in rows},
    "new_source_matches": 0,
}
(out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
print("repeat stable; source difference detected; bad hook rejected", flush=True)
