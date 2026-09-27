"""Rebuild the exact renderer and source-level vector API controls with stock VC6."""

import argparse
import hashlib
import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SCRATCH = ROOT / "tools/match/scratches/projectile_render"
BASE = "08bfc728d"
SOURCE_SHA = "0bdd68c99b01b8f49df47ed8629e5203f372b9b5a4cd50e918cdd765a27f5f26"
VECTOR = "projectile_render_vec2_t"
METRICS = (
    "exact",
    "body_byte_exact",
    "padding_bytes",
    "match_ratio",
    "prefix_instructions",
    "target_instructions",
    "candidate_instructions",
    "references",
    "stack_frame",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def controls(source):
    operand = f"        {VECTOR} other)"
    assert source.count(operand) == 2
    result = f"{VECTOR} result;\n        result = *this;\n        return result;"
    assert source.count(result) == 3
    begin = source.index('extern "C" void projectile_render(')
    return {
        "compound-reference-operand": source.replace(operand, f"        const {VECTOR} &other)"),
        "compound-direct-return": source.replace(result, "return *this;"),
        "scalar-value-constructor": source.replace(
            "const float &x_value, const float &y_value", "float x_value, float y_value",
        ),
        "scalar-value-multiplier": source.replace("const float &scale", "float scale"),
        "direct-camera-components": source.replace("camera_offset[0]", "camera_offset.x").replace(
            "camera_offset[1]", "camera_offset.y",
        ),
        "direct-base-components": source.replace("base[0]", "base.x").replace("base[1]", "base.y"),
        "indexed-muzzle-components": source[:begin]
        + source[begin:].replace("camera_offset_x", "camera_offset[0]").replace("camera_offset_y", "camera_offset[1]"),
    }


def build(config, out, name, source):
    directory = out / name
    directory.mkdir()
    (directory / config.source).write_text(source)
    local = replace(config, directory=directory)
    obj = match.compile_scratch(local, match.DEFAULT_MATCH_ROOT.resolve())
    image, functions, metadata = match._paths_for_image(local.image)
    result = match.run_match(
        obj_path=obj,
        function=local.function,
        image_path=image,
        functions_path=functions,
        metadata_path=metadata,
        symbol_name=local.symbol,
        object_extent=local.archive_extent,
        object_end_symbol=local.archive_end_symbol,
        object_size=local.archive_size,
        end_va=local.end_va,
        reference_aliases=local.reference_aliases,
    )
    payload = match.match_result_payload(result)
    (directory / "diff.txt").write_text("\n".join(result.diff_lines()) + "\n")
    print(name, result.exact, result.body_byte_exact, result.ratio, flush=True)
    return {
        "source_sha256": sha(source.encode()),
        "object_sha256": sha(obj.read_bytes()),
        "metrics": {key: payload[key] for key in METRICS},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    source = (SCRATCH / "scratch.cpp").read_text()
    assert sha(source.encode()) == SOURCE_SHA
    git = shutil.which("git")
    assert git is not None
    before = subprocess.check_output(
        [git, "show", f"{BASE}:tools/match/scratches/projectile_render/scratch.cpp"], cwd=ROOT,
    ).decode()
    config = match.load_scratch_config(SCRATCH)
    cases = {"before": before, "exact": source, **controls(source)}
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = dict(zip(cases, pool.map(lambda item: build(config, args.out, *item), cases.items()), strict=True))
    exact = rows["exact"]["metrics"]
    assert exact["exact"] and exact["body_byte_exact"]
    assert exact["prefix_instructions"] == exact["target_instructions"] == exact["candidate_instructions"] == 3021
    assert exact["references"] == {"ok": 544, "unresolved": 0, "mismatch": 0}
    assert all(not row["metrics"]["body_byte_exact"] for name, row in rows.items() if name != "exact")
    receipt = {
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "config_sha256": sha((SCRATCH / "scratch.conf").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "base_commit": BASE,
        "compiler": config.compiler,
        "cases": rows,
        "scope": "Stock compiler output and relocation-aware whole-function bytes; no compiler intervention or padding.",
    }
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
