"""Export native discovery through the licensed Binary Ninja GUI bridge.

Run with an explicit --target from `bn target list`. New headless PE views are
created in the GUI process; the target's open database is never modified.
Existing reviewed ownership ranges are preserved and their boundary pins checked.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

BN_EXPORT = '''
import binaryninja as bn
import hashlib
import json
from pathlib import Path
registry = json.loads((root / "decomp/builds.json").read_text())
result = []
for build in registry["builds"]:
    for spec in build["images"]:
        if not spec.get("native_inventory"):
            continue
        path = root / build["tree"] / spec["name"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != spec["sha256"]:
            raise ValueError("native inventory image pin differs")
        directory = root / "analysis/decomp" / build["id"] / spec["name"]
        output = directory / spec["native_inventory"]
        previous = json.loads(output.read_text())
        mapped = (directory / "functions.json").read_bytes()
        seeds = [int(row["address"], 16) for row in json.loads(mapped) if row["evidence"] == "exact"]
        view = bn.load(str(path), options={"analysis.mode": "controlFlow"})
        for start in seeds:
            if view.get_function_at(start) is None:
                view.add_function(start)
        view.update_analysis_and_wait()
        functions = []
        for function in sorted(view.functions, key=lambda f: f.start):
            blocks = sorted({(block.start, block.end) for block in function.basic_blocks})
            if blocks:
                # Discovery labels identify an address, never a recovered identity.
                # Analyzer sub_* labels would collide with the curated newer build.
                functions.append({"address": function.start, "name": f"native_function_{function.start:08x}",
                    "blocks": [{"address": lo, "end": hi, "sha256": hashlib.sha256(view.read(lo, hi-lo)).hexdigest()}
                               for lo, hi in blocks]})
        for region in previous["ownership_ranges"]:
            if hashlib.sha256(view.read(region["end"], 64)).hexdigest() != region["boundary_sha256"]:
                raise ValueError("reviewed ownership boundary differs")
        payload = {"schema": 1, "build": build["id"], "image": spec["name"], "sha256": spec["sha256"],
                   "analyzer": {"name": "Binary Ninja", "version": bn.core_version(), "mode": "controlFlow",
                                "seeds": "Verified relinking-invariant bodies from the donor map; independent control-flow discovery retained."},
                   "functions": functions, "verified_starts": seeds,
                   "ownership_ranges": previous["ownership_ranges"], "maps_sha256": hashlib.sha256(mapped).hexdigest()}
        output.write_text(json.dumps(payload, indent=2) + "\\n")
        result.append({"build": build["id"], "image": spec["name"], "functions": len(functions)})
        view.file.close()
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="explicit bn target selector from `bn target list`")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    executable = shutil.which("bn")
    if executable is None:
        raise RuntimeError("bn CLI is unavailable")
    # BN loads the generated script in its own process. Pass the repository path
    # as a Python literal, never through shell interpolation.
    with tempfile.TemporaryDirectory(prefix="crimson-native-export-") as temporary:
        script = Path(temporary) / "export_bn.py"
        script.write_text(f"from pathlib import Path\nroot = Path({str(args.root.resolve())!r})\n" + BN_EXPORT)
        subprocess.run([executable, "--target", args.target, "py", "--script", str(script)], check=True)


if __name__ == "__main__":
    main()
