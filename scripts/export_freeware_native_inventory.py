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
import tempfile
from pathlib import Path
registry = json.loads((root / "decomp/builds.json").read_text())
result = []
for build in registry["builds"]:
    if build_id and build["id"] != build_id:
        continue
    for spec in build["images"]:
        if not spec.get("native_inventory") or (image_name and image_name != spec["name"]):
            continue
        path = root / build["tree"] / spec["name"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != spec["sha256"]:
            raise ValueError("native inventory image pin differs")
        directory = root / "analysis/decomp" / build["id"] / spec["name"]
        output = directory / spec["native_inventory"]
        original = output.read_bytes()
        previous = json.loads(original)
        map_path = directory / "functions.json"
        mapped = map_path.read_bytes()
        seeds = [int(row["address"], 16) for row in json.loads(mapped) if row["evidence"] in ("exact", "interface", "recovered")]
        view = bn.load(str(path), options={"analysis.mode": "controlFlow"})
        for start in list(seeds):
            raw = view.read(start, 5)
            if len(raw) == 5 and raw[0] == 0xE9:
                rel = int.from_bytes(raw[1:5], "little", signed=True)
                target = (start + 5 + rel) & 0xFFFFFFFF
                if target not in seeds:
                    seeds.append(target)
        for start in seeds:
            if view.get_function_at(start) is None:
                view.add_function(start)
        view.update_analysis_and_wait()
        for function in list(view.functions):
            raw = view.read(function.start, 16)
            pad = len(raw) - len(raw.lstrip(b"\\x90\\xcc"))
            if pad > 0 and function.start not in seeds:
                aligned = function.start + pad
                view.remove_user_function(function)
                if aligned < function.highest_address and view.get_function_at(aligned) is None:
                    view.add_function(aligned)
            else:
                raw5 = view.read(function.start, 5)
                if len(raw5) == 5 and raw5[0] == 0xE9:
                    rel = int.from_bytes(raw5[1:5], "little", signed=True)
                    target = (function.start + 5 + rel) & 0xFFFFFFFF
                    if target == function.start + 16 and view.get_function_at(target) is None:
                        view.add_function(target)
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
                   "ownership_ranges": previous["ownership_ranges"], "maps_sha256": hashlib.sha256(mapped).hexdigest(),
                   "platform_replaced": previous["platform_replaced"]}
        view.file.close()
        # Re-exports may race a map rebuild or a reviewed ownership correction.
        # Keep the original visible until all output and input checks finish.
        with tempfile.TemporaryDirectory(dir=directory) as temporary:
            staged = Path(temporary) / output.name
            staged.write_text(json.dumps(payload, indent=2) + "\\n")
            if map_path.read_bytes() != mapped or output.read_bytes() != original:
                raise RuntimeError(f"native inventory inputs changed during export: {directory}")
            staged.replace(output)
        result.append({"build": build["id"], "image": spec["name"], "functions": len(functions)})
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="explicit bn target selector from `bn target list`")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--build", choices=["1.0.2", "1.3.0", "1.4.0"], help="only refresh this freeware build")
    parser.add_argument("--image", choices=["crimson.exe", "grim.dll"], help="only refresh this image in each freeware build")
    args = parser.parse_args()
    executable = shutil.which("bn")
    if executable is None:
        raise RuntimeError("bn CLI is unavailable")
    # BN loads the generated script in its own process. Pass the repository path
    # as a Python literal, never through shell interpolation.
    with tempfile.TemporaryDirectory(prefix="crimson-native-export-") as temporary:
        script = Path(temporary) / "export_bn.py"
        script.write_text(
            "from pathlib import Path\n"
            f"root = Path({str(args.root.resolve())!r})\n"
            f"image_name = {args.image!r}\n"
            f"build_id = {args.build!r}\n"
            + BN_EXPORT,
        )
        subprocess.run([executable, "--target", args.target, "py", "--script", str(script)], check=True)


if __name__ == "__main__":
    main()
