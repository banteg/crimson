"""Isolated compiler intervention; output is diagnostic and never a source match."""

import argparse
import importlib.util
import json
import os
import shutil
import struct
import sys
from pathlib import Path
from unittest.mock import patch

here = Path(__file__).resolve().parent.parent / "vc6-timeline-consumers-2026-09-11"
sys.path.insert(0, str(here))
spec = importlib.util.spec_from_file_location("timeline_trace", here / "trace.py")
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
r = t.r

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
config = t.match.load_scratch_config(t.match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
source = (config.directory / config.source).read_text()
assert r.sha(source.encode()) == t.probes.SOURCE_SHA
assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == t.old.C2_SHA
assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
env = {
    "MSVC_VER": "msvc6.5",
    "CRIMSON_MSVC_ROOT": str(r.COMPILER),
    "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
    "WIBO": str(r.WIBO),
    "CRIMSON_IL_BACKEND": r.windows_path(r.COMPILER / "Bin/C2.DLL"),
}
rows = []
with patch.dict(os.environ, env):
    helper = out / "helper"
    helper.mkdir(exist_ok=True)
    shutil.copyfile(r.HERE / "capture.c", helper / "capture.c")
    r.compile_driver(helper, "capture.c", "capture.obj")
    r.link(helper, "capture.dll", "capture.obj", dll=True)
    for label, src in [
        ("baseline", source),
        ("relative-heading", source.replace("entry->heading", "((float *)template_id)[-1]")),
    ]:
        row, snap = t.trace(config, out, label, src, helper / "capture.dll")
        root = out / label
        for mode in ["control", "reject-template-eligibility"]:
            d = root / mode
            d.mkdir(exist_ok=True)
            shutil.copyfile(root / "replay/replay_settings.h", d / "replay_settings.h")
            observer = (here / "decision_observer.c").read_text()
            if mode != "control":
                old = "    pending[index][9]=regs[7];"
                new = """    pending[index][9]=regs[7];
    if (index >= 2 && watched_temp && pending[index][1] == watched_temp && regs[7]) {
        regs[7] = 0;
        pending[index][11] = 1;
    }"""
                assert observer.count(old) == 1
                observer = observer.replace(old, new)
            (d / "observer.c").write_text(observer)
            r.compile_driver(d, "observer.c", "observer.obj")
            r.link(d, "observer.exe", "observer.obj")
            (d / "replay.obj").unlink(missing_ok=True)
            r.run([r.WIBO, "observer.exe"], d)
            equal = r.normalized_coff(d / "replay.obj") == r.normalized_coff(root / "replay/replay.obj")
            if mode == "control":
                assert equal
            result = t.match.run_match(
                obj_path=d / "replay.obj",
                function=config.function,
                symbol_name=config.symbol,
                reference_aliases=config.reference_aliases,
            )
            (d / "candidate.asm").write_text("\n".join(result.candidate_lines) + "\n")
            (d / "target.asm").write_text("\n".join(result.target_lines) + "\n")
            decisions = list(struct.iter_unpack("<12I", (d / "decisions.bin").read_bytes()))
            changed = [list(x) for x in decisions if x[11]]
            assert len(changed) == int(label == "baseline" and mode != "control")
            metrics = r.function_metrics(config, d / "replay.obj")
            data = {
                "label": label,
                "mode": mode,
                "equal_stock_coff": equal,
                "interventions": changed,
                "preserving_capture_verified": row["observed_whole_coff_equal_except_timestamp"],
                "missing_stream_rejected": row["missing_stream_rejected"],
                "metrics": metrics,
            }
            rows.append(data)
            print(json.dumps(data), flush=True)
(out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
