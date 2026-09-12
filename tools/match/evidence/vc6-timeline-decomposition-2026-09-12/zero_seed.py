"""Locate the common zero temporary in already-preserved compiler replays."""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent / "vc6-timeline-consumers-2026-09-11"
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("t", HERE / "trace.py")
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
r = t.r

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--canonical-root", type=Path, required=True)
parser.add_argument("--witness-root", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
records = []
assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == t.old.C2_SHA
for label, root, expected in [
    ("canonical", args.canonical_root, t.probes.SOURCE_SHA),
    ("witness", args.witness_root, "5ad0be6a087969c28411fe3658c58a1dd2863f4611f4e843d684210f0a257cf9"),
]:
    assert r.sha((root / "captured-source/scratch.cpp").read_bytes()) == expected
    assert r.normalized_coff(root / "observed/replay.obj") == r.normalized_coff(root / "replay/replay.obj")
    snapshots = t.read_trace(root / "observed/phases.bin")
    assert snapshots == json.loads((root / "raw-operands.json").read_text())
    seeds = [n for n in snapshots[7] if n["op"] == 0x163 and n["src"][0][2] & 255 == 7 and n["src"][0][6] == 0]
    assert len(seeds) == 1
    seed = seeds[0]
    temporary = seed["dst"][0][6]
    phases = []
    for phase in range(7, 12):
        definitions = [n for n in snapshots[phase] if n["id"] == seed["id"]]
        users = [n for n in snapshots[phase] if any(op[2] & 255 == 1 and op[6] == temporary for op in n["src"])]
        if phase < 11:
            assert len(definitions) == 1 and definitions[0]["op"] == 0x163 and len(users) == 12
        else:
            assert not definitions and not users
        phases.append({"phase": t.old.PHASES[phase], "seed_nodes": definitions, "users": users})
    records.append(
        {
            "label": label,
            "source_sha256": expected,
            "seed_id": seed["id"],
            "temporary": temporary,
            "observed_coff_equal_except_timestamp": True,
            "phases": phases,
        },
    )
args.out.write_text(json.dumps({"c2_sha256": t.old.C2_SHA, "controls": records}, indent=2) + "\n")
print("Both seeds have 12 users through 0x306c1; both seed identities disappear before 0x336f4")
