"""Check the predicted index scaling and the competing primary-position register."""

import argparse
import json
from pathlib import Path

import verify_controls as controls

HERE = Path(__file__).resolve().parent
match = controls.match
FIELDS = ("address:0x0049bf4c", "address:0x0049bf50")


def has_key(line, keys):
    return any(set(reference.keys).intersection(keys) for reference in line.masked_references)


def region(lines):
    roots = [i for i, line in enumerate(lines) if has_key(line, ("name:creature_find_in_radius",))]
    assert len(roots) == 2
    return lines[roots[0]:roots[1]]


def summarize(lines):
    span = region(lines)
    fields = [line for line in span if has_key(line, FIELDS)]
    retained = [line for i, line in enumerate(span)
                if i < 45 or line in fields or line.text in ("fsub dword [ebp]", "fsub dword [ebx]")]
    return {
        "field_accesses": [{"offset": line.offset, "text": line.text} for line in fields],
        "instructions": [{"offset": line.offset, "text": line.text,
                          "reference_keys": [list(ref.keys) for ref in line.masked_references]}
                         for line in retained],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    results = {}
    for name in ("baseline", "byte-offset-int", "creature-pointer"):
        config, control = controls.reconstruct("projectile_render", name, args.out)
        obj = match.compile_scratch(config)
        body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), config.symbol)
        assert controls.parent.sha(body.data) == control["body_sha256"]
        result = match.run_match(obj_path=obj, function=config.function, symbol_name=config.symbol,
                                 reference_aliases=config.reference_aliases)
        if name == "baseline":
            results["native"] = summarize(result.target_disassembly)
        results[name] = summarize(result.candidate_disassembly)
    native = results["native"]
    baseline = results["baseline"]
    offset = results["byte-offset-int"]
    assert len(native["field_accesses"]) == 6
    assert len(baseline["field_accesses"]) == len(offset["field_accesses"]) == 4
    assert all("[esi+ADDR]" in row["text"] for row in native["field_accesses"] + offset["field_accesses"])
    assert all("[ebx*8+ADDR]" in row["text"] for row in baseline["field_accesses"])
    for name in ("native", "byte-offset-int"):
        assert any(row["text"] == "shl esi, 0x3" for row in results[name]["instructions"])
    for name in ("native", "baseline"):
        assert any(row["text"] == "fsub dword [ebp]" for row in results[name]["instructions"])
    assert any(row["text"] == "fsub dword [ebx]" for row in offset["instructions"])
    overlay = {}
    overlay_bodies = {}
    for name in ("baseline", "early-living_body_size-01", "early-sprite_size-01"):
        config, control = controls.reconstruct("player_render_overlays", name, args.out)
        obj = match.compile_scratch(config)
        body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), config.symbol)
        assert controls.parent.sha(body.data) == control["body_sha256"]
        overlay_bodies[name] = body.data
        overlay[name] = match.run_match(obj_path=obj, function=config.function, symbol_name=config.symbol,
                                       reference_aliases=config.reference_aliases).candidate_disassembly
    assert overlay_bodies["baseline"] == overlay_bodies["early-living_body_size-01"]
    assert len(overlay["baseline"]) == len(overlay["early-sprite_size-01"])
    overlay_changes = [{"baseline_offset": a.offset, "baseline": a.text,
                        "control_offset": b.offset, "control": b.text}
                       for a, b in zip(overlay["baseline"], overlay["early-sprite_size-01"], strict=True)
                       if a.text != b.text]
    assert len(overlay_changes) == 16
    stack_before = HERE.parent / "overlay-muzzle-ownership-2026-09-11/stack-current.json"
    stack_after = HERE / "overlay-stack-early-owned.json"
    before_trace = json.loads(stack_before.read_text())
    after_trace = json.loads(stack_after.read_text())
    assert before_trace["groups"] == after_trace["groups"]
    assert before_trace["observed_coff_sha256"] == after_trace["observed_coff_sha256"]
    assert after_trace["symbols"][4]["kind"] == 4
    assert after_trace["symbols"][4]["final_offset"] == -40
    assert after_trace["symbols"][4]["use_count"] == 4
    receipt = {
        "schema_version": 1,
        "kind": "partial-ion-index-addressing-control",
        "verifier_sha256": controls.parent.sha(Path(__file__).read_bytes()),
        "image_sha256": controls.parent.sha(match.default_image_path().read_bytes()),
        "new_source_matches": 0,
        "limitations": "Selected instructions between paired search calls; no whole-span or whole-function identity. Native retains two additional field reads absent from both candidate controls.",
        "rows": results,
        "overlay": {
            "early_named_body_identical": True,
            "early_sprite_size_changes": overlay_changes,
            "same_stack_groups": True,
            "same_timestamp_normalized_coff": True,
            "stack_trace_hashes": {p.name: controls.parent.sha(p.read_bytes()) for p in (stack_before, stack_after)},
        },
    }
    (args.out / "instructions.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Verified retained 152*i addressing, primary-register displacement and remaining field-read gap")


if __name__ == "__main__":
    main()
