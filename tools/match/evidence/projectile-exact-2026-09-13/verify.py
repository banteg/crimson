"""Rebuild the source graph and prove the complete native encoded function."""

import argparse
import json
import re
from dataclasses import replace
from pathlib import Path

from positions import inspect
from recover import HERE, recover, sha

from crimson import match

IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
STAGES = {"secondary-y8-x-reference", "frame-ad2-offset-xy", "burst-ag2-x-local"}


def metrics(result):
    return {
        "instructions": len(result.candidate_lines),
        "target_instructions": len(result.target_lines),
        "prefix": result.prefix_instructions,
        "references": result.masked_operand_audit.ok_count,
        "reference_problems": result.masked_operand_audit.problem_count,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    graph = json.loads((HERE / "experiments.json").read_text())
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    assert (config.directory / config.source).read_text() == recover()
    rows = []
    final_object = final_result = None
    for index, name in enumerate(("before", *graph["experiments"])):
        directory = args.out / str(index)
        directory.mkdir(exist_ok=True)
        source = recover(name)
        (directory / config.source).write_text(source)
        cfg = replace(config, directory=directory)
        obj = match.compile_scratch(cfg, force=True)
        body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
        expected = graph["before_body_sha256"] if name == "before" else graph["experiments"][name]["body_sha256"]
        assert sha(body.data) == expected, name
        result = match.run_match(
            obj_path=obj, function=cfg.function, symbol_name=cfg.symbol, reference_aliases=cfg.reference_aliases,
        )
        expected_exact = name != "before" and graph["experiments"][name]["exact"]
        assert result.exact == result.body_byte_exact == expected_exact, name
        row = {
            "name": name,
            "source_sha256": sha(source.encode()),
            "body_sha256": sha(body.data),
            "metrics": metrics(result),
        }
        if name in STAGES or name == graph["final"]:
            listing = match.generate_compiler_listing(cfg, output=directory / "listing.cod")
            row["positions"] = inspect(
                result.target_disassembly,
                result.candidate_disassembly,
                listing.listing_path.read_text(encoding="latin1"),
                json.loads(listing.metadata_path.read_text()),
                allow_residuals=name != graph["final"],
            )
        if name == graph["final"]:
            final_object, final_result = obj, result
            final_listing = listing.listing_path.read_text(encoding="latin1")
            final_metadata = json.loads(listing.metadata_path.read_text())
            assert metrics(result) == {
                "instructions": 2203,
                "target_instructions": 2203,
                "prefix": 2203,
                "references": 507,
                "reference_problems": 0,
                "exact": True,
                "body_byte_exact": True,
            }
            assert len(body.data) == sum(line.size for line in result.target_disassembly) == 8409
            assert result.target_padding_bytes == result.candidate_padding_bytes == 0
            assert not result.body_byte_mismatches
            assert row["positions"]["stack_accesses"] == 388
            assert row["positions"]["branches"] == 206
            assert result.target_disassembly[0].address == 0x420B90
            assert result.target_disassembly[-1].address + result.target_disassembly[-1].size == 0x422C69
        rows.append(row)
        print(index + 1, name, "PASS", flush=True)
    assert final_object is not None and final_result is not None
    # The positional certificate must reject altered edges, owners and homes.
    rejected = []
    for kind in ("branch", "reference", "stack"):
        lines = list(final_result.candidate_disassembly)
        if kind == "branch":
            i = next(i for i, line in enumerate(lines) if re.fullmatch(r"j\w+ L[0-9a-f]+", line.text))
            lines[i] = replace(lines[i], text=lines[i].text.split()[0] + " L0")
        elif kind == "reference":
            i = next(i for i, line in enumerate(lines) if line.masked_references)
            refs = list(lines[i].masked_references)
            refs[0] = replace(refs[0], keys=("deliberately-wrong-owner",))
            lines[i] = replace(lines[i], masked_references=tuple(refs))
        else:
            i = next(i for i, line in enumerate(lines) if "[esp+0x" in line.text)
            text = re.sub(r"\[esp\+0x([0-9a-f]+)\]", lambda m: f"[esp+0x{int(m[1], 16) + 4:x}]", lines[i].text)
            lines[i] = replace(lines[i], text=text)
        try:
            inspect(final_result.target_disassembly, lines, final_listing, final_metadata)
        except AssertionError:
            rejected.append(kind)
        else:
            raise AssertionError("Accepted altered " + kind)
    # Actual-source corruption must fail both exactness gates.
    source = recover()
    old = "(float)burst_index * 0.62831855f"
    assert source.count(old) == 1
    changed = source.replace(old, "(float)burst_index * 0.5f")
    directory = args.out / "changed-angle"
    directory.mkdir(exist_ok=True)
    (directory / config.source).write_text(changed)
    obj = match.compile_scratch(replace(config, directory=directory), force=True)
    wrong = match.run_match(
        obj_path=obj, function=config.function, symbol_name=config.symbol, reference_aliases=config.reference_aliases,
    )
    assert not wrong.exact and not wrong.body_byte_exact
    position = next(row for row in rows if row["name"] == graph["final"])["positions"]
    receipt = {
        "schema_version": 1,
        "native_image_sha256": IMAGE_SHA,
        "compiler": config.compiler,
        "cflags": config.cflags,
        "reference_aliases": config.reference_aliases,
        "final_source_sha256": sha(source.encode()),
        "final_object_sha256": sha(final_object.read_bytes()),
        "native_start": 0x420B90,
        "native_end": 0x422C69,
        "encoded_body_bytes": 8409,
        "final": metrics(final_result),
        "final_positions": position,
        "rows": rows,
        "changed_angle_rejected": metrics(wrong),
        "positional_controls_rejected": rejected,
        "new_exact_matches": 1,
        "harness_sha256": {
            path.name: sha(path.read_bytes())
            for path in (*HERE.glob("*.py"), HERE / "before.cpp", HERE / "experiments.json")
        },
        "scope": "Full native code, extent, positional reference and encoded-body identity. Finite execution coverage is recorded separately; original source names are not claimed.",
    }
    frame_helper = HERE.parent / "projectile-stack-groups-2026-09-13" / "primary_homes.py"
    receipt["harness_sha256"]["../projectile-stack-groups-2026-09-13/primary_homes.py"] = sha(frame_helper.read_bytes())
    compiler = match._compiler_executable_path(config, match.DEFAULT_MATCH_ROOT).parent
    receipt["compiler_inputs_sha256"] = {
        name: sha((compiler / name).read_bytes()) for name in ("CL.EXE", "C1XX.DLL", "C2.DLL", "../Include/math.h")
    }
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS exact projectile_update;", len(rows), "source builds; changed-angle control rejected")


if __name__ == "__main__":
    main()
