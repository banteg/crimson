"""Compare the portable FPS sampler with the original Grim DLL at controlled tick intervals."""

import json
import math
from pathlib import Path

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable


def check_freeware_timing(install, edition, lines):
    maps = Path(__file__).resolve().parents[2] / "analysis/decomp" / edition / "grim.dll"
    functions = {row["name"]: int(row["address"], 16) for row in json.loads((maps / "functions.json").read_text())}
    data = {row["name"]: int(row["address"], 16) for row in json.loads((maps / "data.json").read_text())["entries"]}
    grim = NativeOracle(install / "grim.dll", symbols=SymbolTable({}))
    ticks = 0
    if edition != "1.4.0":
        grim.stub_import("QueryPerformanceCounter", 0, pop=4)  # Use Grim's millisecond fallback.
    grim.stub_import("timeGetTime", lambda _: ticks)
    grim.write_f32(data["grim_ms_to_seconds_scale"], .001)
    rows = [line.split() for line in lines if line.startswith("timing ")]
    assert len(rows) == 11
    for _, step, actual in rows:
        ticks += int(step)
        grim.call(functions["grim_timing_update"])
        expected = grim.read_f32(data["grim_fps"])
        assert math.isclose(float(actual), expected, abs_tol=1e-5), (edition, ticks, actual, expected)
