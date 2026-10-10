"""Compare optimized Plaguebearer and orbit math to the recovered bodies."""

import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
ROOT = CORE.parent
spec = importlib.util.spec_from_file_location("adapter", CORE / "adapter.py")
assert spec and spec.loader
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


def main():
    compiler = shutil.which("clang++")
    if not compiler:
        raise SystemExit("clang++ is required")
    with tempfile.TemporaryDirectory() as folder:
        out = Path(folder)
        optimized = adapter.load_diffs(adapter.DIFFS)
        baseline = adapter.load_diffs(tuple(p for p in adapter.DIFFS if p.name != "optimizations"))
        for path in (ROOT / "tools/match/include").glob("*.h"):
            rel = str(path.relative_to(ROOT))
            text = adapter.apply_diffs(rel, path.read_text(), optimized)
            (out / path.name).write_text(adapter.prototypes(path, text, adapter.PROTOTYPES))
        rel = "decomp/1.9/crimsonland/crimsonland/plaguebearer_spread_infection.cpp"
        path = ROOT / rel
        sources = []
        for label, hunks in (("baseline", baseline), ("optimized", optimized)):
            text = adapter.adapt(path, adapter.apply_diffs(rel, path.read_text(), hunks))
            text = text.replace("plaguebearer_spread_infection", label + "_plaguebearer_spread_infection")
            source = out / (label + "_plague.cpp")
            source.write_text(text)
            sources.append(str(source))
        rel = "decomp/1.9/crimsonland/crimsonland/creature_update_all.cpp"
        path = ROOT / rel
        text = adapter.adapt(path, adapter.apply_diffs(rel, path.read_text(), optimized))
        # Compile the actual generated cache helper; replay parity covers its AI callers.
        start = text.index("struct optimization_orbit_trig")
        end = text.index("struct creature_vec2_t")
        (out / "orbit-cache.inc").write_text(text[start:end])
        subprocess.run(
            [
                compiler,
                "-std=c++17",
                "-O2",
                "-fms-extensions",
                "-fno-strict-aliasing",
                "-fwrapv",
                "-ffp-contract=off",
                "-Wno-ignored-attributes",
                "-Wno-write-strings",
                "-include",
                str(CORE / "host/hooks.h"),
                "-I" + str(CORE / "host"),
                "-I" + str(out),
                "-I" + str(ROOT / "third_party/headers"),
                *sources,
                str(CORE / "checks/creature_optimizations.cpp"),
                "-o",
                str(out / "check"),
            ],
            check=True,
        )
        subprocess.run([str(out / "check")], check=True)


if __name__ == "__main__":
    main()
